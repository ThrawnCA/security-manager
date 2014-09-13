package id.antuar.carl.security;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.FilePermission;
import java.security.AllPermission;
import java.security.Permission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertTrue;

/**
 * Ensure that the GuestPass pseudo-permission correctly interacts
 * with the Permission system.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class GuestPassTest {

  /** 'Set I/O' action for RuntimePermission. */
  private static final String SET_IO = "setIO";

  /** Read action for FilePermission. */
  private static final String READ = "read";

  /** Read+write actions for FilePermission. */
  private static final String READ_WRITE = "read,write";

  /** Test file location. */
  private static final String TEST_FILE = "target/foo";

  /**
   * @return Permission parameters and expected results.
   */
  @DataProvider
  public Object[][] permissionParams() {
    return new Object[][] {
      {AllPermission.class.getName(), null, null,
        AbstractCustomSecurityManager.ALL_PERM },
      {AllPermission.class.getName(), "", "",
        AbstractCustomSecurityManager.ALL_PERM },
      {RuntimePermission.class.getName(), SET_IO, null,
        new RuntimePermission(SET_IO) },
      {RuntimePermission.class.getName(), SET_IO, "",
        new RuntimePermission(SET_IO) },
      {FilePermission.class.getName(), TEST_FILE, READ_WRITE,
        new FilePermission(TEST_FILE, READ_WRITE) },
    };
  }

  /**
   * @return Permissions for implication comparison.
   */
  @DataProvider
  public Object[][] impliedPermissions() {
    final GuestPass guestPass =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ_WRITE);

    return new Object[][] {
      {guestPass, new FilePermission(TEST_FILE, READ), Boolean.FALSE },
      {guestPass,
        makeGuestPass(FilePermission.class.getName(), TEST_FILE + "-baz", READ),
        Boolean.FALSE },
      {guestPass,
        makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ),
        Boolean.TRUE },
    };
  }

  /**
   * @return Permissions for equality comparison.
   */
  @DataProvider
  public Object[][] equalPermissions() {
    final Permission guestPass1 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ);
    final Permission guestPass2 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ);
    final Permission guestPass3 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ_WRITE);
    final Permission otherPermission =
      makePermission(AllPermission.class.getName(), "", "");
    return new Object[][] {
      {guestPass1, guestPass2, Boolean.TRUE },
      {guestPass1, guestPass3, Boolean.FALSE },
      {guestPass1, otherPermission, Boolean.FALSE },
    };
  }

  /**
   * Ensure that string parameters result in the expected permission.
   * @param className The class of the real permission.
   * @param permissionName The name of the real permission.
   * @param actions The actions of the real permission.
   * @param expected The real permission that should result.
   */
  @Test(dataProvider = "permissionParams")
  public void shouldLoadSpecifiedPermissions(final String className,
                                             final String permissionName,
                                             final String actions,
                                             final Permission expected) {
    assertEquals(
      makePermission(className, permissionName, actions),
      expected,
      "Permission not correctly loaded"
    );
  }

  /**
   * Ensure that one GuestPass implies only another GuestPass
   * for a real permission that is implied by the first's real permission.
   * @param guestPass Guest pass for comparison.
   * @param other Permission that may or may not be implied by 'guestPass'.
   * @param shouldImply Whether we expect 'guestPass' to imply 'other'.
   */
  @Test(dataProvider = "impliedPermissions")
  public void shouldImplyGuestPassForImpliedPermission(
      final GuestPass guestPass,
      final Permission other,
      final boolean shouldImply) {
    if (shouldImply) {
      assertTrue(guestPass.implies(other), guestPass + " implies " + other);
    } else {
      assertFalse(guestPass.implies(other), guestPass + " implies " + other);
    }
  }

  /**
   * Ensure that GuestPass equals only other GuestPass for the same permission.
   * @param guestPass Guest pass for comparison.
   * @param other Permission that may or may not be equal to 'guestPass'.
   * @param shouldMatch Whether we expect 'guestPass' to equal 'other'.
   */
  @Test(dataProvider = "equalPermissions")
  public void shouldEqualGuestPassForSamePermission(final GuestPass guestPass,
                                                    final Permission other,
                                                    final boolean shouldMatch) {
    if (shouldMatch) {
      assertEquals(other, guestPass,
        "Should equal guest pass for same permission");
    } else {
      assertNotEquals(other, guestPass,
        "Should equal only guest pass for same permission");
    }
  }

  /**
   * Verify that toString looks the way we expect.
   */
  @Test
  public void shouldRenderToStringIncludingRealPermission() {
    assertEquals(
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ_WRITE)
        .toString(),
      "(\"id.antuar.carl.security.GuestPass\" "
      + "(\"java.io.FilePermission\" \"target/foo\" \"read,write\"))"
      , "Incorrect toString output"
    );
  }

  /**
   * Construct a GuestPass without throwing checked exceptions.
   * Throw AssertionError instead.
   * @param className The class name of the real permission.
   * @param permissionName The permission name of real the permission, if any.
   * @param actions The actions of the real permission, if any.
   * @return A GuestPass for the specified real permission.
   */
  private static GuestPass makeGuestPass(final String className,
                                         final String permissionName,
                                         final String actions) {
    try {
      return new GuestPass(className, permissionName, actions);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to construct GuestPass", e);
    }
  }

  /**
   * Construct a Permission without throwing checked exceptions.
   * Throw AssertionError instead.
   * @param className The class name of the permission.
   * @param permissionName The permission name of the permission, if any.
   * @param actions The actions of the permission, if any.
   * @return A Permission object representing the specified permission.
   */
  private static Permission makePermission(final String className,
                                           final String permissionName,
                                           final String actions) {
    try {
      return GuestPass.toPermission(className, permissionName, actions);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to construct permission", e);
    }
  }

}
