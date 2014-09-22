package id.thrawnca.security;

import java.security.BasicPermission;

/**
 * Permission used just for unit testing.
 * @author Carl Antuar
 */
public final class TestPermission extends BasicPermission {

  /** We don't really need this, but meh. */
  private static final long serialVersionUID = 20140918L;

  /** BasicPermission doesn't seem to preserve this. */
  private final String permissionActions;

  /**
   * Constructs a new TestPermission.
   * @param name Whatever test permissions are wanted.
   */
  public TestPermission(final String name) {
    this(name, "<no actions>");
  }

  /**
   * Constructs a new TestPermission.
   * @param name Whatever test permissions are wanted.
   * @param actions Used only in describing the permission.
   * Helpful for identifying test cases.
   */
  public TestPermission(final String name, final String actions) {
    super(name);
    permissionActions = actions;
  }

  /**
   * @return String representation of this permission. Format is
   * <classname> "<permission name>", "<actions>"
   */
  @Override
  public String toString() {
    return new StringBuilder(getClass().getName())
      .append(" \"")
      .append(getName())
      .append("\", \"")
      .append(permissionActions)
      .append('"')
      .toString();
  }

}
