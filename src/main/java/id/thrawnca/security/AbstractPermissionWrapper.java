package id.thrawnca.security;

import java.lang.reflect.Constructor;
import java.security.Permission;
import java.util.Arrays;

/**
 * A permission that decorates another permission with custom behavior.
 *
 * @author Carl Antuar
 */
public abstract class AbstractPermissionWrapper extends Permission {

  /** Serialization ID - might not be needed. */
  private static final long serialVersionUID = 20141224L;

  /**
   * The wrapped permission.
   */
  private final Permission realPermission;

  /**
   * @param name The permission name to use in this wrapper.
   * @param className The class name of the wrapped permission.
   * @param parameters Any parameters to construct the wrapped permission,
   * separated by a pipeline |
   * @exception ReflectiveOperationException If the wrapped permission
   * cannot be constructed from the given class name and arguments.
   */
  public AbstractPermissionWrapper(
      final String name,
      final String className,
      final String parameters
    ) throws ReflectiveOperationException {
    this(name, toPermission(className, parameters));
  }

  /**
   * Construct a wrapper for the specified permission.
   * @param name The permission name to use in this wrapper.
   * @param perm The permission to wrap.
   */
  public AbstractPermissionWrapper(final String name, final Permission perm) {
    super(name);
    realPermission = perm;
  }

  /**
   * @return The permission wrapped by this wrapper.
   */
  protected final Permission getPermission() {
    return realPermission;
  }

  /**
   * @param className The class name of the permission.
   * @param parameters Constructor parameters, if any, separated by pipelines |.
   * @return A Permission object representing the specified permission.
   * @exception ReflectiveOperationException If a permission
   * cannot be constructed from the given class name and arguments.
   */
  protected static Permission toPermission(
      final String className,
      final String parameters
    ) throws ReflectiveOperationException {
    String[] splitParameters;
    if (parameters == null || parameters.length() == 0) {
      splitParameters = new String[] {};
    } else {
      splitParameters = parameters.split("\\|");
    }

    final Class<?> permissionClass = Class.forName(className);
    final Constructor constructor =
      getBestFitConstructor(permissionClass, splitParameters.length);
    if (constructor == null) {
      throw new IllegalArgumentException(
        "No constructor found for class " + permissionClass
        + " and parameter(s) [" + parameters + ']'
      );
    }
    final Class[] argTypes = new Class[constructor.getParameterTypes().length];
    Arrays.fill(argTypes, String.class);

    // include all provided parameters and use blanks for any extras needed
    final String[] constructorArgs = new String[argTypes.length];
    System.arraycopy(
      splitParameters, 0, constructorArgs, 0, splitParameters.length
    );
    Arrays.fill(
      constructorArgs, splitParameters.length, constructorArgs.length, ""
    );
    return (Permission) constructor.newInstance(constructorArgs);
  }

  /**
   * Chooses the best-fit Constructor from the specified class.
   * This constructor may need more parameters than supplied.
   * @param clazz The class to search.
   * @param parameterCount The number of parameters supplied.
   * @return The constructor that best fits the number of parameters,
   * or null if none is suitable.
   */
  protected static Constructor getBestFitConstructor(
      final Class clazz,
      final int parameterCount
    ) {
    final Constructor<?>[] constructors = clazz.getConstructors();
    Constructor bestConstructor = null;
    for (int i = 0; i < constructors.length; i++) {
      final Class<?>[] parameterTypes = constructors[i].getParameterTypes();
      // ensure constructor can take all the parameters we have been given
      boolean suitable = parameterTypes.length >= parameterCount;
      // ensure constructor can accept strings for all parameters
      for (int j = 0; suitable && j < parameterTypes.length; j++) {
        if (!parameterTypes[j].isAssignableFrom(String.class)) {
          suitable = false;
        }
      }
      if (suitable
        && (bestConstructor == null
          || parameterTypes.length < bestConstructor.getParameterTypes().length)
        ) {
        bestConstructor = constructors[i];
      }
    }
    return bestConstructor;
  }

  /**
   * Convenience method for subclasses to compare wrapped permissions.
   * @param other The object to check.
   * @return TRUE iff other is a permission wrapper
   * and our wrapped permission equals the wrapped permission in 'other'.
   */
  protected final boolean wrappedEquals(final Object other) {
    return other instanceof AbstractPermissionWrapper
      && realPermission.equals(
        ((AbstractPermissionWrapper) other).realPermission
      );
  }

  /**
   * Convenience method for subclasses to compare wrapped permissions.
   * @param other The object to check.
   * @return TRUE iff other is a permission wrapper
   * and our wrapped permission implies the wrapped permission in 'other'.
   */
  protected final boolean wrappedImplies(final Permission other) {
    return other instanceof AbstractPermissionWrapper
      && realPermission.implies(
        ((AbstractPermissionWrapper) other).realPermission
      );
  }


  /**
   * @return String representation of this wrapper,
   * including the permission it wraps.
   */
  @Override
  public final String toString() {
    return new StringBuilder("(\"")
      .append(getClass().getName())
      .append("\" ")
      .append(getPermission())
      .append(')')
      .toString();
  }


}
