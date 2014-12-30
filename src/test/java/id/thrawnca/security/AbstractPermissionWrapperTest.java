package id.thrawnca.security;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.FilePermission;
import java.security.AllPermission;
import java.security.Permission;
import java.util.logging.LoggingPermission;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

/**
 * Ensure that AbstractPermissionWrapper correctly interacts
 * with wrapped permissions.
 *
 * @author Carl Antuar
 */
@SuppressWarnings("PMD.AtLeastOneConstructor")
public final class AbstractPermissionWrapperTest {

  /** 'Set I/O' action for RuntimePermission. */
  private static final String SET_IO = "setIO";

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
      {AllPermission.class.getName(), null,
        AbstractCustomSecurityManager.ALL_PERM },
      {AllPermission.class.getName(), "",
        AbstractCustomSecurityManager.ALL_PERM },
      {LoggingPermission.class.getName(), "control",
        new LoggingPermission("control", "") },
      {RuntimePermission.class.getName(), SET_IO,
        new RuntimePermission(SET_IO) },
      {RuntimePermission.class.getName(), SET_IO,
        new RuntimePermission(SET_IO) },
      {FilePermission.class.getName(), TEST_FILE + '|' + READ_WRITE,
        new FilePermission(TEST_FILE, READ_WRITE) },

      {Class.class.getName(), "", null},
      {AllPermission.class.getName(), "one|two|three", null},
    };
  }

  /**
   * Ensure that string parameters result in the expected permission, or an
   * appropriate exception is thrown when a permission could not be assembled.
   * @param className The class of the real permission.
   * @param parameters Any parameters to construct the permission.
   * @param expected The real permission that should result,
   * or null if failure is expected.
   */
  @Test(dataProvider = "permissionParams")
  public void shouldLoadSpecifiedPermissions(
      final String className,
      final String parameters,
      final Object expected
    ) {
    if (expected == null) {
      try {
        makePermissionWrapper(className, parameters);
        fail("Should not have successfully constructed wrapper for class "
          + className + " and parameter(s) " + parameters);
      } catch (IllegalArgumentException e) {
        assertTrue(e.getMessage().contains("No constructor found"),
          "Expected 'no constructor found' but saw " + e.getMessage()
        );
      }
    } else {
      assertEquals(
        makePermissionWrapper(className, parameters).getPermission(),
        expected,
        "Permission not correctly loaded"
      );
    }
  }

  /**
   * Check that constructor identification ignores constructors
   * with non-String argument types.
   * @exception ReflectiveOperationException Should not occur
   * unless the test conditions are wrong.
   */
  @Test
  public void shouldIgnoreConstructorsWithNonStringArguments()
    throws ReflectiveOperationException {
    assertEquals(
      AbstractPermissionWrapper.getBestFitConstructor(
        AbstractPermissionWrapper.class, 2),
      AbstractPermissionWrapper.class.getConstructor(
        String.class,
        String.class,
        String.class
      ),
      "Expected to use 3-String constructor"
    );
  }

  /**
   * Ensure that no exception is thrown when checking whether we are equal to
   * a non-wrapper.
   */
  @Test
  public void shouldGracefullyHandleEquallingNonWrapper() {
    assertNotEquals(
      new TestPermission("foo"),
      makePermissionWrapper(TestPermission.class.getName(), "foo"),
      "Wrapper should not equal non-wrapper"
    );
  }

  /**
   * Verify that toString looks the way we expect.
   */
  @Test
  public void shouldRenderToStringIncludingRealPermission() {
    final Permission perm = makePermissionWrapper(
      FilePermission.class.getName(), TEST_FILE + '|' + READ_WRITE
    );
    assertEquals(perm.toString(),
      "(\"" + perm.getClass().getName()
      + "\" (\"java.io.FilePermission\" \"target/foo\" \"read,write\"))"
      , "Incorrect toString output"
    );
  }

  /**
   * Construct a permission wrapper without throwing checked exceptions.
   * Throw AssertionError instead.
   * @param className The class name of the real permission.
   * @param parameters Any parameters to construct the permission.
   * @return A wrapper for the specified real permission.
   */
  private static AbstractPermissionWrapper makePermissionWrapper(
      final String className,
      final String parameters
    ) {
    try {
      return new PermissionWrapperStub("test", className, parameters);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to construct wrapper from "
        + className + ", " + parameters + ": " + e.getMessage(), e);
    }
  }

  /**
   * Test permission wrapper with stub implementations.
   */
  public static final class PermissionWrapperStub
    extends AbstractPermissionWrapper {

    /** We don't really need this, but meh. */
    private static final long serialVersionUID = 20141227L;

    /**
     * @param name The permission name to use in this wrapper.
     * @param className The class name of the wrapped permission.
     * @param parameters Any parameters to construct the wrapped permission,
     * separated by a pipeline |
     * @exception ReflectiveOperationException If the wrapped permission
     * cannot be constructed from the given class name and arguments.
     */
    public PermissionWrapperStub(
        final String name,
        final String className,
        final String parameters
      ) throws ReflectiveOperationException {
      super(name, className, parameters);
    }

    /**
     * @param other The permission to ignore.
     * @return FALSE
     */
    @Override
    public boolean implies(final Permission other) {
      return wrappedImplies(other);
    }

    /**
     * @param other The object to ignore.
     * @return FALSE
     */
    @Override
    public boolean equals(final Object other) {
      return wrappedEquals(other);
    }

    /**
     * @return 0
     */
    @Override
    public int hashCode() {
      return 0;
    }

    /**
     * @return null.
     */
    @Override
    public String getActions() {
      return null;
    }
  }

}
