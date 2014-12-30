package id.thrawnca.security;

import java.security.Permission;

/**
 * A pseudo-permission, recognised only by our custom security manager.
 *
 * When granted, it permits the holder to be present on the call stack
 * when the wrapped permission is checked, IFF there is also a class present
 * that holds the real version of the wrapped permission.
 * @author Carl Antuar
 */
public final class GuestPass extends AbstractPermissionWrapper {

  /** The permission name used by guest passes. */
  public static final String PERMISSION_NAME = "callStackPresence";

  /** Serialization ID - might not be needed. */
  private static final long serialVersionUID = 20141224L;

  /**
   * Intended to be called by the JVM when loading from a policy file.
   * @param className The class name of the real permission
   * @param parameters Any parameters to construct the real permission,
   * separated by a pipeline |
   * @exception ReflectiveOperationException If the permission
   * cannot be constructed from the given class name and arguments.
   */
  public GuestPass(final String className, final String parameters)
      throws ReflectiveOperationException {
    this(toPermission(className, parameters));
  }

  /**
   * Construct a GuestPass for the specified permission.
   * @param perm The permission to wrap.
   */
  public GuestPass(final Permission perm) {
    super(PERMISSION_NAME, perm);
  }

  /**
   * @return Empty string; GuestPass has no actions of its own.
   */
  @Override
  public String getActions() {
    return "";
  }

  /**
   * @param permission The permission for which we are seeking.
   * @return TRUE iff 'permission' is a GuestPass whose wrapped permission
   * is implied by this GuestPass' wrapped permission.
   * NB This will not work properly with java.security.Permissions.
   */
  @Override
  public boolean implies(final Permission permission) {
    /*
     * Problems here. java.security.Permissions keeps a map of runtime classes
     * to permission collections, and only checks the collection to determine
     * whether a permission is implied. So a GuestPass
     * can never successfully imply a different type of permission wrapper.
     */
    return getName().equals(permission.getName()) && wrappedImplies(permission);
  }

  /**
   * @param other The object to check for equality.
   * @return TRUE iff 'other' is a GuestPass whose wrapped permission
   * is equal to this GuestPass' wrapped permission.
   */
  @Override
  public boolean equals(final Object other) {
    return other instanceof GuestPass && wrappedEquals(other);
  }

  /**
   * @return The hash code of the wrapped permission.
   */
  @Override
  public int hashCode() {
    return getPermission().hashCode();
  }

}
