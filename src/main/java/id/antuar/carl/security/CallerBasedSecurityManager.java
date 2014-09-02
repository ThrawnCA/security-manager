package id.antuar.carl.security;

import java.security.AccessControlException;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Collection;

/**
 * This SecurityManager checks the most recent non-system class
 * on the call stack, instead of every class.
 *
 * This is not suitable for sandboxing Java Applets;
 * however, in a J2EE context, it allows us to greatly reduce
 * the number of permissions granted to third-party libraries,
 * which may ultimately result in greater security,
 * since those libraries, if compromised by crafted input,
 * will be unprivileged.
 *
 * @author Carl Antuar
 */
public class CallerBasedSecurityManager extends SecurityManager {

  /**
   * This is determined by the presence of the system property
   * 'java.security.manager.log_mode'.
   * If present, then security violations will result in a log of the
   * requested permission, in a suitable format for copying into a
   * policy file, instead of an exception.
   */
  private static final boolean LOG_MODE;

  /** Output format for logging needed permissions. */
  private static final String PERMISSION_FORMAT;

  /** Package prefixes for Java API packages. */
  private static final Collection<String> SYSTEM_PACKAGES;

  /** Private helper to manage our special privileges. */
  private static final PrivilegedActor ACTOR;

  static {
    LOG_MODE = System.getProperty("java.security.manager.log_mode") != null;
    PERMISSION_FORMAT = "grant codeBase \"%s\" {%n  permission %s;%n} // (%s)";
    SYSTEM_PACKAGES = Arrays.asList("java.", "sun.", "com.jrockit.");
    ACTOR = new PrivilegedActor();
  }

  /**
   * @param clazz A class object from the call stack.
   * @return TRUE if the specified class is a built-in JDK/JRE class;
   * otherwise FALSE.
   */
  static boolean isSystemClass(final Class clazz) {
    if (clazz.getClassLoader() != Object.class.getClassLoader()) {
      return false;
    }
    for (String packagePrefix : SYSTEM_PACKAGES) {
      if (clazz.getName().startsWith(packagePrefix)) {
        return true;
      }
    }
    return false;
  }

  /**
   * @param callStack The call stack being examined.
   * @return The most recent non-system class on the call stack,
   * excluding the security manager itself.
   */
  static Class getLastCaller(final Class... callStack) {
    for (Class clazz : callStack) {
      if (clazz == CallerBasedSecurityManager.class) {
        continue;
      }
      if (!isSystemClass(clazz)) {
        return clazz;
      }
    }
    return null;
  }

  /**
   * Checks whether the most recent non-system class on the stack
   * has the specified permission.
   * Throws a SecurityException if the permission is not granted.
   * @param perm The permission that is being sought.
   */
  public final void checkPermission(final Permission perm) {
    Class[] callStack = getClassContext();
    for (int i = 2; i < callStack.length; i++) {
      if (callStack[i] == PrivilegedActor.class
          && callStack[i + 1] == CallerBasedSecurityManager.class) {
        return;
      }
    }
    Class clazz = getLastCaller(callStack);
    if (clazz == null) {
      return;
    }
    ProtectionDomain domain = ACTOR.getProtectionDomain(clazz);
    if (!ACTOR.implies(domain, perm)) {
      if (LOG_MODE) {
        System.err.println(
          String.format(PERMISSION_FORMAT,
            domain.getCodeSource().getLocation(),
            perm.toString().replace("\" \"", "\", \"").replaceAll("[()]", ""),
            clazz.getName()
          )
        );
      } else {
        throw new AccessControlException("access denied: " + perm, perm);
      }
    }
  }

  /**
   * The SecurityManager needs extra privileges
   * to interact with the security system,
   * but these privileges should be restricted to other callers,
   * which puts it in the risky position of being 'setuid' code,
   * potentially liable to abuse if it can be tricked into running other
   * arbitrary code.
   *
   * We reduce the risk by delegating privileges to a private helper,
   * and only granting access when the SecurityManager calls the helper.
   * To ensure that all is well, we simply need to check that:
   * - The helper does not do anything that might execute untrusted code.
   * - The SecurityManager does not give the helper's results
   * to any other code.
   */
  private static class PrivilegedActor {
    /**
     * @param clazz The class whose protection domain we want.
     * @return The ProtectionDomain for the class.
     */
    ProtectionDomain getProtectionDomain(final Class clazz) {
      return clazz.getProtectionDomain();
    }

    /**
     * @param domain The ProtectionDomain of the class we are checking.
     * @param perm The permission that we are checking for.
     * @return TRUE if the ProtectionDomain holds 'perm',
     * or holds a permission that implies 'perm';
     * otherwise FALSE.
     */
    boolean implies(final ProtectionDomain domain, final Permission perm) {
      return domain.implies(perm);
    }
  }
}
