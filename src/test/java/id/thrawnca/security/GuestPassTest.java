package id.thrawnca.security;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.FilePermission;
import java.security.AllPermission;
import java.security.Permission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;

/**
 * Ensure that the GuestPass pseudo-permission correctly interacts
 * with the Permission system.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class GuestPassTest {

  /** Read action for FilePermission. */
  private static final String READ = "read";

  /** Read+write actions for FilePermission. */
  private static final String READ_WRITE = "read,write";

  /** Test file location. */
  private static final String TEST_FILE = "target/foo";

  /**
   * @return Permissions for implication comparison.
   */
  @DataProvider
  public Object[][] impliedPermissions() {
    final GuestPass guestPass =
      makeGuestPass(FilePermission.class.getName(),
        TEST_FILE + '|' + READ_WRITE);

    return new Object[][] {
      {guestPass, new FilePermission(TEST_FILE, READ), Boolean.FALSE },
      {guestPass,
        new TestPermission(GuestPass.PERMISSION_NAME),
        Boolean.FALSE },
      {guestPass,
        makeGuestPass(FilePermission.class.getName(),
          TEST_FILE + "-baz" + '|' + READ),
        Boolean.FALSE },
      {guestPass,
        makeGuestPass(FilePermission.class.getName(), TEST_FILE + '|' + READ),
        Boolean.TRUE },
    };
  }

  /**
   * @return Permissions for equality comparison.
   */
  @DataProvider
  public Object[][] equalPermissions() {
    final Permission guestPass =
      makeGuestPass(FilePermission.class.getName(), TEST_FILE + '|' + READ);

    return new Object[][] {
      {guestPass,
        makeGuestPass(FilePermission.class.getName(), TEST_FILE + '|' + READ),
        Boolean.TRUE },
      {guestPass,
        makeGuestPass(FilePermission.class.getName(),
          TEST_FILE + '|' + READ_WRITE),
        Boolean.FALSE },
      {guestPass, new AllPermission(), Boolean.FALSE },
      {guestPass,
        new TestPermission(GuestPass.PERMISSION_NAME),
        Boolean.FALSE },
      {guestPass,
        new Object(),
        Boolean.FALSE },
    };
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
      final boolean shouldImply
    ) {
    assertEquals(
      guestPass.implies(other),
      shouldImply,
      guestPass + " implies " + other
    );
  }

  /**
   * Ensure that GuestPass equals only other GuestPass for the same permission.
   * @param guestPass Guest pass for comparison.
   * @param other Object that may or may not be equal to 'guestPass'.
   * @param shouldMatch Whether we expect 'guestPass' to equal 'other'.
   */
  @Test(dataProvider = "equalPermissions")
  public void shouldEqualGuestPassForSamePermission(
      final GuestPass guestPass,
      final Object other,
      final boolean shouldMatch
    ) {
    if (shouldMatch) {
      assertEquals(other, guestPass,
        "Should equal guest pass for same permission");
    } else {
      assertNotEquals(other, guestPass,
        "Should equal only guest pass for same permission");
    }
  }

  /**
   * Check that hashCode follows contract.
   */
  @Test
  public void shouldGiveEqualHashCodeForEqualObjects() {
    final Permission testPermission = new TestPermission("foo", "guest pass");
    assertEquals(
      new GuestPass(testPermission).hashCode(),
      new GuestPass(testPermission).hashCode(),
      "Equal objects must have equal hashCodes"
    );
  }

  /**
   * Ensure that guest passes have no actions of their own.
   */
  @Test
  public void shouldHaveNoActions() {
    assertEquals(
      makeGuestPass(
        FilePermission.class.getName(), TEST_FILE + '|' + READ
      ).getActions(),
      "",
      "Guest passes should not have any actions of their own"
    );
  }

  /**
   * Construct a GuestPass without throwing checked exceptions.
   * Throw AssertionError instead.
   * @param className The class name of the real permission.
   * @param parameters Any parameters to construct the permission.
   * @return A GuestPass for the specified real permission.
   */
  private static GuestPass makeGuestPass(
      final String className,
      final String parameters
    ) {
    try {
      return new GuestPass(className, parameters);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to construct GuestPass from "
        + className + ", " + parameters + ": " + e.getMessage(), e);
    }
  }

}
