package id.thrawnca.security;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.Permission;

import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.fail;

/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
public final class CallerBasedSecurityManagerTest {

  /** Convenience string for permission name that is granted to tests. */
  public static final String GRANTED = "granted";

  /** Convenience string for permission name that is not granted to tests. */
  public static final String NOT_GRANTED = "notGranted";

  /** Singleton security manager. */
  private final CallerBasedSecurityManager manager;

  /**
   * Construct a singleton security manager for use in tests.
   */
  public CallerBasedSecurityManagerTest() {
    manager = new CallerBasedSecurityManager();
  }

  /**
   * @return Call stacks that should not be granted the specified permissions.
   */
  @DataProvider
  public Object[][] unprivileged() {
    final Class withPerm = CallerBasedSecurityManagerTest.class;
    final Class withoutPerm = Test.class;
    final Class system = Object.class;
    return new Object[][] {
      {
        new Class[] {
          withPerm
        }, new TestPermission(NOT_GRANTED, "wrong permission")
      },
      {
        new Class[] {
          system,
          withoutPerm
        }, new TestPermission(GRANTED, "unprivileged and system")
      },
      {
        new Class[] {
          withoutPerm
        }, new TestPermission(GRANTED, "unprivileged only")
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
          CallerBasedSecurityManagerTest.class
        }, new TestPermission(GRANTED, "privileged only")
      },
      {
        new Class[] {
          CallerBasedSecurityManagerTest.class,
          Test.class
        }, new TestPermission(GRANTED, "privileged then unprivileged")
      },
      {
        new Class[] {
          Object.class,
          System.class
        }, new TestPermission(NOT_GRANTED, "all-system stack")
      },
      {
        new Class[] {
          CallerBasedSecurityManagerTest.class,
          CallerBasedSecurityManager.class
        }, new TestPermission(GRANTED, "privileged and security manager")
      },
    };
  }

  /**
   * Ensure that the last non-system caller is correctly detected.
   */
  @Test
  public void shouldDetectLastNonSystemCaller() {
    final Class<?> managerClass = manager.getClass();
    final Class<?> testClass = CallerBasedSecurityManagerTest.class;
    final Class<?> systemClass = Object.class;
    assertSame(
      CallerBasedSecurityManager.getLastCaller(
        managerClass,
        managerClass,
        systemClass,
        managerClass,
        testClass
      ),
      managerClass,
      "Wrong caller identified"
    );
  }

  /**
   * Completely-privileged stacks should be ignored.
   */
  @Test
  public void shouldReturnNullForAllSystemStack() {
    assertNull(
      CallerBasedSecurityManager.getLastCaller(
        Object.class,
        Object.class,
        Object.class
      ), "No caller expected for all-system stack"
    );
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
    manager.checkPermission(perm, callStack);
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
      manager.checkPermission(perm, callStack);
    } catch (SecurityException e) {
      fail("Expected permission " + perm + " to be granted");
    }
  }

}
