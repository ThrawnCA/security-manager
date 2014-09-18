package id.thrawnca.security;

import java.security.BasicPermission;

/**
 * Permission used just for unit testing.
 * @author Carl Antuar
 */
public final class TestPermission extends BasicPermission {

  /** We don't really need this, but meh. */
  private static final long serialVersionUID = 20140918L;

  /**
   * Constructs a new TestPermission.
   * @param name Whatever test permissions are wanted.
   */
  public TestPermission(final String name) {
    super(name);
  }

}
