package id.antuar.carl.security;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Collection;

/**
 * This SecurityManager checks the most recent non-system class
 * on the call stack, instead of every class.
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

  /** Package prefixes for Java API packages. */
  private static final Collection<String> SYSTEM_PACKAGES;

  /** Private helper to manage our special privileges. */
  private static final PrivilegedActor ACTOR;

  static {
    LOG_MODE = System.getProperty("java.security.manager.log_mode") != null;
    SYSTEM_PACKAGES = Arrays.asList("java.", "sun.");
    ACTOR = new PrivilegedActor();
  }

  /**
   * @param clazz A class object from the call stack.
   * @return TRUE if the specified class is a built-in JDK/JRE class;
   * otherwise FALSE.
   */
  protected static boolean isSystemClass(final Class clazz) {
    boolean isSystem = false;
    if (clazz.getClassLoader() == Object.class.getClassLoader()) {
      for (final String packagePrefix : SYSTEM_PACKAGES) {
        if (clazz.getName().startsWith(packagePrefix)) {
          isSystem = true;
          break;
        }
      }
    }
    return isSystem;
  }

  /**
   * @param callStack The call stack being examined.
   * @return The most recent non-system class on the call stack,
   * excluding the security manager itself.
   */
  protected static Class getLastCaller(final Class... callStack) {
    Class lastCaller = null;
    for (final Class clazz : callStack) {
      if (clazz != CallerBasedSecurityManager.class && !isSystemClass(clazz)) {
        lastCaller = clazz;
        break;
      }
    }
    return lastCaller;
  }

  /**
   * Checks whether the most recent non-system class on the stack
   * has the specified permission.
   * Throws a SecurityException if the permission is not granted.
   * @param perm The permission that is being sought.
   */
  public final void checkPermission(final Permission perm) {
    final Class[] callStack = getClassContext();
    for (int i = 2; i < callStack.length; i++) {
      if (callStack[i] == PrivilegedActor.class
          && callStack[i + 1] == CallerBasedSecurityManager.class) {
        return;
      }
    }
    final Class clazz = getLastCaller(callStack);
    if (clazz == null) {
      return;
    }
    final ProtectionDomain domain = ACTOR.getProtectionDomain(clazz);
    if (!ACTOR.implies(domain, perm)) {
      // failure
      if (LOG_MODE) {
        System.err.println(
          new StringBuilder("grant codeBase \"")
            .append(domain.getCodeSource().getLocation())
            .append("\" {\n  permission ")
            .append(perm)
            .append(";\n} // ")
            .append(clazz.getName())
            .toString()
        );
      } else {
        throw new SecurityException("access denied: " + perm);
      }
    }
  }

  /**
   * Private helper that is permitted to ignore privilege checks
   * iff called by the security manager.
   */
  private static class PrivilegedActor {

    /**
     * @param clazz The class whose protection domain we want.
     * @return The ProtectionDomain for the class.
     */
    public ProtectionDomain getProtectionDomain(final Class clazz) {
      return clazz.getProtectionDomain();
    }

    /**
     * @param domain The ProtectionDomain of the class we are checking.
     * @param perm The permission that we are checking for.
     * @return TRUE if the ProtectionDomain holds 'perm',
     * or holds a permission that implies 'perm';
     * otherwise FALSE.
     */
    public boolean implies(final ProtectionDomain domain,
                           final Permission perm) {
      return domain.implies(perm);
    }
  }
}
