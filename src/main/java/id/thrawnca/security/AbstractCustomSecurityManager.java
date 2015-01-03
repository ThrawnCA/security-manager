package id.thrawnca.security;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.security.AllPermission;
import java.security.Permission;
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
   * 'thrawnca.security.manager.log_mode'.
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
    return ACTOR.implies(ACTOR.getProtectionDomain(clazz), ALL_PERM);
  }

  /**
   * Determines whether to bypass security checks.
   * This method MUST NOT use any calls that require privileges.
   * @param callStack The call stack to examine.
   * @return TRUE iff the call stack includes the privileged helper.
   */
  private boolean hasSecurityBypass(final Class... callStack) {
    boolean bypass = false;
    for (int i = 1; !bypass && i < callStack.length; i++) {
      if (callStack[i] == PrivilegedActor.class) {
        bypass = true;
      }
    }
    return bypass;
  }

  /**
   * Checks whether the current call stack has the specified permission.
   * Throws a SecurityException if the permission is not granted.
   * @param perm The permission that is being sought.
   */
  public final void checkPermission(final Permission perm) {
    if (this == System.getSecurityManager()) {
      final Class[] callStack = trimCallStack(getClassContext());
      if (!hasSecurityBypass(callStack)) {
        checkPermissionForContext(perm, callStack, getDomains(callStack));
      }
    }
  }

  /**
   * Checks whether the supplied security context has the specified permission.
   * Throws a SecurityException if the permission is not granted.
   * @param perm The permission that is being sought.
   * @param context The security context seeking the permission.
   */
  public final void checkPermission(
      final Permission perm,
      final Object context) {
    if (this == System.getSecurityManager()) {
      if (!(context instanceof SecurityContext)) {
        throw new SecurityException("Wrong security context type: " + context);
      }
      final SecurityContext securityContext = (SecurityContext) context;
      final Class[] callStack = ACTOR.getClassContext(securityContext);
      // we don't seem to need a check for the helper here
      checkPermissionForContext(
        perm,
        callStack,
        ACTOR.getDomains(securityContext)
      );
    }
  }

  /**
   * @return An object that encapsulates the current security environment.
   */
  public final Object getSecurityContext() {
    final Class[] callStack = trimCallStack(getClassContext());
    return new SecurityContext(callStack, getDomains(callStack));
  }

  /**
   * Trim the security manager off the start of the call stack.
   * NB This includes parents of the runtime type of the security manager.
   * @param callStack The call stack to trim.
   * @return The call stack without the security manager at the start.
   */
  protected final Class[] trimCallStack(final Class<?>... callStack) {
    int startIndex = 0;
    while (callStack[startIndex].isAssignableFrom(getClass())) {
      startIndex++;
    }
    final Class[] trimmedCallStack = new Class[callStack.length - startIndex];
    System.arraycopy(
      callStack, startIndex, trimmedCallStack, 0, trimmedCallStack.length
    );
    return trimmedCallStack;
  }

  /**
   * Retrieves the protection domains for the specified classes
   * using the privileged actor. These should only be given to trusted code.
   * @param classes The classes to retrieve protection domains for.
   * @return The protection domains for the specified list of classes.
   */
  // returned map is unmodifiable
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  private Map<Class, ProtectionDomain> getDomains(final Class... classes) {
    final Map<Class, ProtectionDomain> domains =
      new HashMap<Class, ProtectionDomain>(classes.length);
    for (int i = 0; i < classes.length; i++) {
      if (!domains.containsKey(classes[i])) {
        domains.put(classes[i], ACTOR.getProtectionDomain(classes[i]));
      }
    }
    return Collections.unmodifiableMap(domains);
  }

  /**
   * Checks the call stack against the specified permission.
   * @param perm The permission needed.
   * @param callStack The call stack to check.
   * @param protectionDomains The protection domains for the call stack.
   */
  protected abstract void checkPermissionForContext(
      Permission perm,
      Class[] callStack,
      Map<Class, ProtectionDomain> protectionDomains);

  /**
   * Handle a security failure, either by logging the required permission,
   * or throwing a security exception, depending on configuration.
   * @param perm The permission that was needed.
   * @param classes The class(es) that did not have sufficient permissions.
   */
  protected final void handleFailure(
      final Permission perm,
      final Class... classes
    ) {
    if (logMode) {
      for (int i = 0; i < classes.length; i++) {
        logFailure(ACTOR.getProtectionDomain(classes[i]), perm);
      }
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
     * This needs to be privileged in case we need to read the policy file(s).
     * @param domain The protection domain we want to check.
     * @param perm The permission we are checking for.
     * @return Whether the protection domain implies the permission.
     */
    protected boolean implies(
        final ProtectionDomain domain,
        final Permission perm) {
      return domain.implies(perm);
    }

    /**
     * @param context The security context to unpack.
     * @return The call stack from the context.
     */
    protected Class[] getClassContext(final SecurityContext context) {
      return context.getClassContext();
    }

    /**
     * @param context The security context to unpack.
     * @return The protection domains from the context.
     */
    protected Map<Class, ProtectionDomain> getDomains(
        final SecurityContext context) {
      return context.getProtectionDomains();
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
      final StringBuilder output = new StringBuilder(1000);
      while (domains.hasNext()) {
        final Map.Entry<ProtectionDomain, Set<Permission>> entry =
          domains.next();
        output.append("grant codeBase \"")
          .append(entry.getKey().getCodeSource().getLocation())
          .append("\" {\n");
        final Iterator<Permission> permissions = entry.getValue().iterator();
        while (permissions.hasNext()) {
          output.append("  permission ")
            .append(permissions.next())
            .append(";\n");
        }
        output.append("}\n");
      }
      System.err.print(output);
    }
  }
}
