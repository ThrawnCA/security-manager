package id.thrawnca.security;

import java.lang.reflect.Constructor;
import java.security.Permission;
import java.util.Arrays;

/**
 * A pseudo-permission, recognised only by our custom security manager.
 *
 * When granted, it permits the holder to be present on the call stack
 * when the wrapped permission is checked, IFF there is also a class present
 * that holds the real version of the wrapped permission.
 * @author Carl Antuar
 */
public final class GuestPass extends Permission {

  /** Serialization ID - might not be needed. */
  private static final long serialVersionUID = 20140910L;

  /**
   * The real permission, for which the holder of this GuestPass
   * is allowed to be present.
   */
  private final Permission realPermission;

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
    super("callStackPresence");
    realPermission = perm;
  }

  /**
   * @return The real permission wrapped by this GuestPass.
   */
  protected Permission getPermission() {
    return realPermission;
  }

  /**
   * @param permission The permission for which we are seeking.
   * @return TRUE iff 'permission' is a GuestPass whose wrapped permission
   * is implied by this GuestPass' wrapped permission.
   */
  @Override
  public boolean implies(final Permission permission) {
    return permission instanceof GuestPass
      && realPermission.implies(((GuestPass) permission).realPermission);
  }

  /**
   * @return Empty string. GuestPass has no actions of its own.
   */
  @Override
  public String getActions() {
    return "";
  }

  /**
   * @param other The object to check for equality.
   * @return TRUE iff 'other' is a GuestPass whose wrapped permission
   * is equal to this GuestPass' wrapped permission.
   */
  @Override
  public boolean equals(final Object other) {
    return other instanceof GuestPass
      && realPermission.equals(((GuestPass) other).realPermission);
  }

  /**
   * @return The hash code of the wrapped permission.
   */
  @Override
  public int hashCode() {
    return realPermission.hashCode();
  }

  /**
   * @param className The class name of the permission.
   * @param parameters Parameters to construct the permission, if any,
   * separated by pipelines |.
   * @return A Permission object representing the specified permission.
   * @exception ReflectiveOperationException If a permission
   * cannot be constructed from the given class name and arguments.
   */
  protected static Permission toPermission(
      final String className,
      final String parameters
    ) throws ReflectiveOperationException {
    final Class<?> permissionClass = Class.forName(className);
    Constructor constructor;
    String[] constructorArgs;
    if (parameters == null || parameters.length() == 0) {
      constructor = permissionClass.getConstructor();
      constructorArgs = new String[] {};
    } else {
      constructorArgs = parameters.split("\\|");
      final Class[] argTypes = new Class[constructorArgs.length];
      Arrays.fill(argTypes, String.class);
      constructor = permissionClass.getConstructor(argTypes);
    }
    return (Permission) constructor.newInstance(constructorArgs);
  }

  /**
   * @return String representation of this GuestPass,
   * including the real permission it stands for.
   */
  @Override
  public String toString() {
    return new StringBuilder("(\"")
      .append(getClass().getName())
      .append("\" ")
      .append(realPermission)
      .append(')')
      .toString();
  }

}
