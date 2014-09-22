package id.thrawnca.security;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.Permission;

import static org.testng.Assert.fail;

/**
 * Ensure, as much as possible, that the GuestAwareSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class GuestAwareSecurityManagerTest {

  /** Convenience string for permission name that is granted to tests. */
  public static final String GRANTED = "granted";

  /** Convenience string for permission name that is not granted to tests. */
  public static final String NOT_GRANTED = "notGranted";

  /**
   * @return Call stacks that should not be granted the specified permissions.
   */
  @DataProvider
  public Object[][] unprivileged() {
    return new Object[][] {
      {
        new Class[] {
          GuestAwareSecurityManagerTest.class
        }, new TestPermission(NOT_GRANTED, "wrong permission")
      },
      {
        new Class[] {
          GuestAwareSecurityManagerTest.class,
          Test.class
        }, new TestPermission(NOT_GRANTED, "guest and wrong permission")
      },
      {
        new Class[] {
          Object.class,
          Test.class
        }, new TestPermission(GRANTED, "guest and system")
      },
      {
        new Class[] {
          Test.class
        }, new TestPermission(GRANTED, "guest only")
      },
      {
        new Class[] {
          GuestAwareSecurityManagerTest.class,
          GuestAwareSecurityManager.class
        }, new TestPermission(GRANTED, "security manager on stack")
      },
    };
  }

  /**
   * @return Call stacks that should be granted the specified permissions.
   */
  @DataProvider
  public Object[][] privileged() {
    return new Object[][] {
      {
        new Class[] {
          GuestAwareSecurityManagerTest.class
        }, new TestPermission(GRANTED, "privileged only")
      },
      {
        new Class[] {
          GuestAwareSecurityManagerTest.class,
          Test.class
        }, new TestPermission(GRANTED, "privileged and guest")
      },
      {
        new Class[] {
          Test.class,
          GuestAwareSecurityManagerTest.class
        }, new TestPermission(GRANTED, "guest and privileged")
      },
      {
        new Class[] {
          Object.class,
          System.class
        }, new TestPermission(NOT_GRANTED, "all system classes")
      },
    };
  }

  /**
   * Ensure that exception is thrown for permission we don't have.
   * @param callStack The call stack that should be unprivileged.
   * @param perm The permission that callStack should not have.
   */
  @Test(expectedExceptions = SecurityException.class,
    dataProvider = "unprivileged")
  public void shouldThrowSecurityExceptionForUnprivilegedCode(
      final Class[] callStack,
      final Permission perm
    ) {
    new GuestAwareSecurityManager()
      .checkPermission(callStack, perm);
    fail("Should not have been granted " + perm);
  }

  /**
   * Ensure that we are granted permissions we do have.
   * @param callStack The call stack that should be privileged.
   * @param perm The permission that callStack should have.
   */
  @Test(dataProvider = "privileged")
  public void shouldNotThrowSecurityExceptionForPrivilegedCode(
      final Class[] callStack,
      final Permission perm
    ) {
    try {
      new GuestAwareSecurityManager().checkPermission(callStack, perm);
    } catch (SecurityException e) {
      fail("Expected permission " + perm + " to be granted");
    }
  }

}
