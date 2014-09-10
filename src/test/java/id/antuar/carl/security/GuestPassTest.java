package id.antuar.carl.security;

import org.junit.Assert;
import org.junit.Test;

import java.io.FilePermission;
import java.security.AllPermission;
import java.security.Permission;

/**
 * Ensure that the GuestPass pseudo-permission correctly interacts
 * with the Permission system.
 *
 * @author Carl Antuar
 */
// unit tests don't need explicit constructors
@SuppressWarnings("PMD.AtLeastOneConstructor")
public class GuestPassTest {

  /** Read action for FilePermission. */
  private static final String READ = "read";

  /** Read+write actions for FilePermission. */
  private static final String READ_WRITE = "read,write";

  /** Test file location. */
  private static final String TEST_FILE = "target/foo";

  /**
   * Ensure that permissions without arguments can be loaded.
   */
  @Test
  public final void shouldLoadRealPermissionWithNoPermissionName() {
    Permission permission =
      makePermission("java.security.AllPermission", null, null);
    final Permission expected = new AllPermission();
    Assert.assertEquals("Should have constructed java.security.AllPermission",
      expected, permission);
    permission = makePermission("java.security.AllPermission", "", "");
    Assert.assertEquals("Should have constructed java.security.AllPermission",
      expected, permission);
  }

  /**
   * Ensure that permissions with just permission name can be loaded.
   */
  @Test
  public final void shouldLoadRealPermissionWithPermissionName() {
    Permission permission =
      makePermission("java.lang.RuntimePermission", "setIO", null);
    final Permission expected = new RuntimePermission("setIO");
    Assert.assertEquals("Should have constructed 'setIO' permission",
      expected, permission);
    permission = makePermission("java.lang.RuntimePermission", "setIO", "");
    Assert.assertEquals("Should have constructed 'setIO' permission",
      expected, permission);
  }

  /**
   * Ensure that permissions with permission name and actions can be loaded.
   */
  @Test
  public final void shouldLoadRealPermissionWithPermissionNameAndActions() {
    final Permission permission =
      makePermission(FilePermission.class.getName(), TEST_FILE, READ_WRITE);
    Assert.assertEquals("Should have constructed r/w permission for 'foo'",
      new FilePermission(TEST_FILE, READ_WRITE), permission);
  }

  /**
   * Ensure that one GuestPass implies only another GuestPass
   * for a real permission that is implied by the first's real permission.
   */
  @Test
  public final void shouldImplyGuestPassForImpliedPermission() {
    final GuestPass guestPass =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ_WRITE);
    Assert.assertFalse(
      "Should not have implied read permission for 'foo'",
      guestPass.implies(new FilePermission(TEST_FILE, READ))
    );
    Assert.assertFalse(
      "Should not have implied guest read permission for 'foo-baz'",
      guestPass.implies(
        makeGuestPass(FilePermission.class.getName(), TEST_FILE + "-baz", READ)
      )
    );
    Assert.assertTrue(
      "Should have implied guest read permission for 'foo'",
      guestPass.implies(
        makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ)
      )
    );
  }

  /**
   * Ensure that GuestPass equals only other GuestPass for the same permission.
   */
  @Test
  public final void shouldEqualGuestPassForSamePermission() {
    final Permission guestPass1 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ);
    final Permission guestPass2 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ);
    final Permission guestPass3 =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE, READ_WRITE);
    final Permission otherPermission =
      makePermission(AllPermission.class.getName(), null, null);
    Assert.assertEquals(
      "Should equal guest pass for same permission",
      guestPass1, guestPass2
    );
    Assert.assertNotEquals(
      "Should not equal guest pass for different permission",
      guestPass1, guestPass3
    );
    Assert.assertNotEquals(
      "Should not equal non-guest pass",
      guestPass1, otherPermission
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
