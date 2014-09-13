package id.antuar.carl.security;

import java.security.Permission;
import java.security.AllPermission;
import java.security.ProtectionDomain;

/**
 * Provides methods useful for security manager implementations.
 *
 * @author Carl Antuar
 */
public abstract class AbstractCustomSecurityManager extends SecurityManager {

  /** Private helper to manage our special privileges. */
  private static final PrivilegedActor ACTOR = new PrivilegedActor();

  /** Singleton instance of AllPermission. */
  protected static final AllPermission ALL_PERM = new AllPermission();

  /**
   * The system property that controls log mode.
   */
  protected static final String LOG_PROPERTY = "java.security.manager.log_mode";

  /**
   * This is determined by the presence of the system property
   * 'java.security.manager.log_mode'.
   * If present, then security violations will result in a log of the
   * requested permission, in a suitable format for copying into a
   * policy file, instead of an exception.
   */
  private final boolean logMode = System.getProperty(LOG_PROPERTY) != null;

  /**
   * @param clazz A class object from the call stack.
   * @return TRUE if the specified class holds AllPermission; otherwise FALSE.
   */
  protected static boolean isSystemClass(final Class clazz) {
    return ACTOR.implies(clazz, ALL_PERM);
  }

  /**
   * Determines whether to bypass security checks.
   * This method MUST NOT use any calls that require privileges.
   * @param callStack The call stack to examine.
   * @return TRUE iff the call stack includes the privileged helper.
   */
  protected final boolean hasSecurityBypass(final Class... callStack) {
    boolean bypass = false;
    for (int i = 2; !bypass && i < callStack.length; i++) {
      if (callStack[i] == PrivilegedActor.class) {
        bypass = true;
      }
    }
    return bypass;
  }

  /**
   * Checks whether the most recent non-system class on the stack
   * has the specified permission.
   * Throws a SecurityException if the permission is not granted.
   * @param perm The permission that is being sought.
   */
  public final void checkPermission(final Permission perm) {
    final Class[] callStack = getClassContext();
    if (!hasSecurityBypass(callStack)) {
      checkPermission(callStack, perm);
    }
  }

  /**
   * Checks the call stack against the specified permission.
   * @param callStack The call stack to check.
   * @param perm The permission needed.
   */
  protected abstract void checkPermission(Class[] callStack, Permission perm);

  /**
   * Use the helper to check the privileges of a class.
   * @param clazz The class we are checking.
   * @param perm The permission that we are checking for.
   * @return TRUE iff the class holds 'perm',
   * or holds a permission that implies 'perm'.
   */
  protected static boolean implies(final Class clazz,
                                   final Permission perm) {
    return ACTOR.implies(clazz, perm);
  }

  /**
   * Handle a security failure, either by logging the required permission,
   * or throwing a security exception, depending on configuration.
   * @param clazz The class that did not have sufficient permissions.
   * @param perm The permission that was needed.
   */
  protected final void handleFailure(final Class clazz,
                                     final Permission perm) {
    if (logMode) {
      System.err.println(
        new StringBuilder("grant codeBase \"")
          .append(ACTOR.getProtectionDomain(clazz)
            .getCodeSource().getLocation())
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

  /**
   * Private helper that is permitted to ignore privilege checks.
   */
  private static class PrivilegedActor {

    /**
     * @param clazz The class whose protection domain we want.
     * @return The ProtectionDomain for the class.
     */
    protected ProtectionDomain getProtectionDomain(final Class clazz) {
      return clazz.getProtectionDomain();
    }

    /**
     * @param clazz The class we are checking.
     * @param perm The permission that we are checking for.
     * @return TRUE if the class holds 'perm',
     * or holds a permission that implies 'perm'; otherwise FALSE.
     */
    protected boolean implies(final Class clazz,
                           final Permission perm) {
      return clazz.getProtectionDomain().implies(perm);
    }
  }
}
