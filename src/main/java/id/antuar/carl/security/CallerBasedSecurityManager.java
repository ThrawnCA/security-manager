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

  static {
    LOG_MODE = System.getProperty("java.security.manager.log_mode") != null;
    PERMISSION_FORMAT = "grant codeBase \"%s\" {%n  permission %s%n} // (%s)";
    SYSTEM_PACKAGES = Arrays.asList("java.", "sun.", "com.jrockit.");
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
      if (callStack[i] == getClass()) {
        return;
      }
    }
    Class clazz = getLastCaller(callStack);
    if (clazz == null) {
      return;
    }
    ProtectionDomain domain = clazz.getProtectionDomain();
    if (!domain.implies(perm)) {
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
}
