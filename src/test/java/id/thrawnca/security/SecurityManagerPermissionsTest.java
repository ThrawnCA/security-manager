package id.thrawnca.security;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertTrue;
import static org.testng.Assert.assertFalse;

/**
 * Check whether the custom SecurityManager implementations
 * grant or deny permissions correctly.
 *
 * @author Carl Antuar
 */
public final class SecurityManagerPermissionsTest {

  /** Convenience string for permission name that is granted to tests. */
  public static final String GRANTED = "granted";

  /** Convenience string for permission name that is not granted to tests. */
  public static final String NOT_GRANTED = "notGranted";

  /** Error message when permission is wrongly granted. */
  public static final String UNEXPECTED_GRANT = "Should not have granted %s";

  /** Error message when permission is wrongly denied. */
  public static final String UNEXPECTED_DENY = "Should have granted %s";

  /** Caller-based security manager. */
  private final CallerBasedSecurityManager callerBased;

  /** Guest-aware security manager. */
  private final GuestAwareSecurityManager guestAware;

  /**
   * Construct a singleton security manager for use in tests.
   */
  public SecurityManagerPermissionsTest() {
    callerBased = new CallerBasedSecurityManager();
    guestAware = new GuestAwareSecurityManager();
  }

  /**
   * Ensure that the permission system has been loaded properly.
   * Also ensures that necessary class files are loaded
   * before installing the always-fail security manager.
   */
  @BeforeClass
  public void ensureSetUp() {
    assertTrue(
      SecurityManagerPermissionsTest.class.getProtectionDomain().implies(
        new TestPermission(GRANTED)
      ), "Test permission 'granted' not loaded correctly"
    );
    assertTrue(
      SecurityManagerPermissionsTest.class.getProtectionDomain().implies(
        AbstractCustomSecurityManagerTest.SET_SECURITY
      ), "'setSecurityManager' permission not loaded correctly"
    );
    assertTrue(
      Test.class.getProtectionDomain().implies(
        new GuestPass(new TestPermission(GRANTED))
      ), "Guest pass for test permission not loaded correctly"
    );
    assertTrue(
      Test.class.getProtectionDomain().implies(
        new GuestPass(AbstractCustomSecurityManagerTest.SET_SECURITY)
      ), "Guest pass for 'setSecurityManager' permission not loaded correctly"
    );
  }

  /**
   * Assemble a map of protection domains. NB This method is not privileged.
   * @param classes The classes needed for testing.
   * @return The protection domains for the test classes.
   */
  // returned map is unmodifiable
  @SuppressWarnings("PMD.UseConcurrentHashMap")
  public static Map<Class, ProtectionDomain> getDomains(
      final Class... classes) {
    final Map<Class, ProtectionDomain> domains =
      new HashMap<Class, ProtectionDomain>(classes.length);
    for (int i = 0; i < classes.length; i++) {
      domains.put(
        classes[i],
        classes[i].getProtectionDomain()
      );
    }
    return Collections.unmodifiableMap(domains);
  }

  /**
   * Assemble a security context. NB This method is not privileged.
   * @param classes The call stack associated with a security context.
   * @return A SecurityContext object for the call stack.
   */
  public static SecurityContext getSecurityContext(final Class... classes) {
    return new SecurityContext(classes, getDomains(classes));
  }

  /**
   * Check whether a permission is granted.
   * @param manager The security manager to consult.
   * @param callStack The call stack whose privileges we are checking.
   * @param perm The permission that we are checking for.
   * @return Whether the security manager granted the permission.
   */
  // not worth adding an extra local variable here
  // and it would trip the DataFlowAnomalyAnalysis rule
  @SuppressWarnings("PMD.OnlyOneReturn")
  public static boolean isPermissionGranted(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm
    ) {
    try {
      manager.checkPermissionForContext(perm, callStack, getDomains(callStack));
      return true;
    } catch (SecurityException e) {
      return false;
    }
  }

  /**
   * Check whether a permission is granted when using a context snapshot.
   * @param manager The security manager to consult.
   * @param callStack The call stack whose privileges we are checking.
   * @param perm The permission that we are checking for.
   * @return Whether the security manager granted the permission.
   */
  // not worth adding an extra local variable here
  // and it would trip the DataFlowAnomalyAnalysis rule
  @SuppressWarnings("PMD.OnlyOneReturn")
  public static boolean isPermissionGrantedUsingSnapshot(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm
    ) {
    final Object context = getSecurityContext(callStack);
    try {
      System.setSecurityManager(manager);
      manager.checkPermission(perm, context);
      return true;
    } catch (SecurityException e) {
      return false;
    } finally {
      System.setSecurityManager(null);
    }
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
        callerBased,
        new Class[] {
          withPerm
        }, new TestPermission(NOT_GRANTED, "wrong permission")
      },
      {
        callerBased,
        new Class[] {
          system,
          withoutPerm
        }, new TestPermission(GRANTED, "unprivileged and system")
      },
      {
        callerBased,
        new Class[] {
          withoutPerm
        }, new TestPermission(GRANTED, "unprivileged only")
      },

      {
        guestAware,
        new Class[] {
          SecurityManagerPermissionsTest.class
        }, new TestPermission(NOT_GRANTED, "wrong permission")
      },
      {
        guestAware,
        new Class[] {
          SecurityManagerPermissionsTest.class,
          Test.class
        }, new TestPermission(NOT_GRANTED, "guest and wrong permission")
      },
      {
        guestAware,
        new Class[] {
          Object.class,
          Test.class
        }, new TestPermission(GRANTED, "guest and system")
      },
      {
        guestAware,
        new Class[] {
          Test.class
        }, new TestPermission(GRANTED, "guest only")
      },
      {
        guestAware,
        new Class[] {
          SecurityManagerPermissionsTest.class,
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
        callerBased,
        new Class[] {
          CallerBasedSecurityManagerTest.class
        }, new TestPermission(GRANTED, "privileged only")
      },
      {
        callerBased,
        new Class[] {
          CallerBasedSecurityManagerTest.class,
          Test.class
        }, new TestPermission(GRANTED, "privileged then unprivileged")
      },
      {
        callerBased,
        new Class[] {
          Object.class,
          System.class
        }, new TestPermission(NOT_GRANTED, "all-system stack")
      },
      {
        callerBased,
        new Class[] {
          CallerBasedSecurityManagerTest.class,
          CallerBasedSecurityManager.class
        }, new TestPermission(GRANTED, "privileged and security manager")
      },

      {
        guestAware,
        new Class[] {
          SecurityManagerPermissionsTest.class
        }, new TestPermission(GRANTED, "privileged only")
      },
      {
        guestAware,
        new Class[] {
          SecurityManagerPermissionsTest.class,
          Test.class
        }, new TestPermission(GRANTED, "privileged and guest")
      },
      {
        guestAware,
        new Class[] {
          Test.class,
          SecurityManagerPermissionsTest.class
        }, new TestPermission(GRANTED, "guest and privileged")
      },
      {
        guestAware,
        new Class[] {
          Object.class,
          System.class
        }, new TestPermission(NOT_GRANTED, "all system classes")
      },
    };
  }

  /**
   * Ensure that exception is thrown for permission we don't have.
   * @param manager The security manager to consult.
   * @param callStack The call stack that should be unprivileged.
   * @param perm The permission that callStack should not have.
   */
  @Test(dataProvider = "unprivileged")
  public void shouldThrowSecurityExceptionForUnprivilegedCode(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm) {
    assertFalse(isPermissionGranted(manager, callStack, perm),
      String.format(UNEXPECTED_GRANT, perm));
  }

  /**
   * Ensure that we are granted permissions we do have.
   * @param manager The security manager to consult.
   * @param callStack The call stack that should be privileged.
   * @param perm The permission that callStack should have.
   */
  @Test(dataProvider = "privileged")
  public void shouldNotThrowSecurityExceptionForPrivilegedCode(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm) {
    assertTrue(isPermissionGranted(manager, callStack, perm),
      String.format(UNEXPECTED_DENY, perm));
  }

  /**
   * Ensure that exception is thrown for permission we don't have
   * when using a context snapshot.
   * @param manager The security manager to consult.
   * @param callStack The call stack that should be unprivileged.
   * @param perm The permission that callStack should not have.
   */
  @Test(dataProvider = "unprivileged")
  public void shouldThrowSecurityExceptionForUnprivilegedCodeUsingSnapshot(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm
    ) {
    assertFalse(isPermissionGrantedUsingSnapshot(manager, callStack, perm),
      String.format(UNEXPECTED_GRANT, perm));
  }

  /**
   * Ensure that we are granted permissions we do have
   * when using a context snapshot.
   * @param manager The security manager to consult.
   * @param callStack The call stack that should be privileged.
   * @param perm The permission that callStack should have.
   */
  @Test(dataProvider = "privileged")
  public void shouldNotThrowSecurityExceptionForPrivilegedCodeUsingSnapshot(
      final AbstractCustomSecurityManager manager,
      final Class[] callStack,
      final Permission perm) {
    assertTrue(isPermissionGrantedUsingSnapshot(manager, callStack, perm),
      String.format(UNEXPECTED_DENY, perm));
  }

}
