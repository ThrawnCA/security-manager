package id.thrawnca.security;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
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
  protected static final String LOG_PROPERTY =
    "thrawnca.security.manager.log_mode";

  /**
   * This is determined by the presence of the system property
   * 'java.security.manager.log_mode'.
   * If present, then security violations will result in a log of the
   * requested permission, in a suitable format for copying into a
   * policy file, instead of an exception.
   */
  private final boolean logMode;

  /** Collection of logged failures, if we are in log mode. */
  private final Map<ProtectionDomain, Set<Permission>> permissionsNeeded;

  /**
   * Constructs a new security manager.
   * If 'thrawnca.security.manager.log_mode' is set,
   * then it is created in log mode;
   * otherwise, it is in enforcement mode.
   */
  public AbstractCustomSecurityManager() {
    super();
    logMode = Boolean.parseBoolean(System.getProperty(LOG_PROPERTY));
    if (logMode) {
      permissionsNeeded = new HashMap<ProtectionDomain, Set<Permission>>();
      Runtime.getRuntime().addShutdownHook(
        new Thread(new FailedPermissionsLogger(permissionsNeeded))
      );
    } else {
      permissionsNeeded = null;
    }
  }

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
      logFailure(ACTOR.getProtectionDomain(clazz), perm);
    } else {
      throw new SecurityException("access denied: " + perm);
    }
  }

  /**
   * Record that a PermissionDomain needs extra permission to run.
   * @param domain The ProtectionDomain with insufficient permissions.
   * @param perm The extra permission needed.
   */
  private void logFailure(
      final ProtectionDomain domain,
      final Permission perm
    ) {
    if (!permissionsNeeded.containsKey(domain)) {
      permissionsNeeded.put(domain, new HashSet<Permission>());
    }
    permissionsNeeded.get(domain).add(perm);
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

  /**
   * Outputs all of the failed permissions from this run.
   */
  private static class FailedPermissionsLogger implements Runnable {

    /** The permissions that have been needed and not granted. */
    private final Map<ProtectionDomain, Set<Permission>> permissionsNeeded;

    /**
     * @param permissionMap A reference to
     * the map of permissions that will be logged.
     * NB The contents of this map may be externally altered
     * before the logger is actually run.
     */
    public FailedPermissionsLogger(
        final Map<ProtectionDomain, Set<Permission>> permissionMap
      ) {
      permissionsNeeded = permissionMap;
    }

    /**
     * Output all of the permission failures from this VM execution
     * to the standard error stream.
     */
    public void run() {
      final Iterator<Map.Entry<ProtectionDomain, Set<Permission>>> domains =
        permissionsNeeded.entrySet().iterator();
      while (domains.hasNext()) {
        final Map.Entry<ProtectionDomain, Set<Permission>> entry =
          domains.next();
        System.err.print("grant codeBase \"");
        System.err.print(entry.getKey().getCodeSource().getLocation());
        System.err.println("\" {");
        final Iterator<Permission> permissions = entry.getValue().iterator();
        while (permissions.hasNext()) {
          System.err.print("  permission ");
          System.err.print(permissions.next());
          System.err.println(';');
        }
        System.err.println('}');
      }
    }
  }
}
