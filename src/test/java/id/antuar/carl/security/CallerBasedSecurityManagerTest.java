package id.antuar.carl.security;

import org.junit.After;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.security.AllPermission;
import java.security.Permission;
import java.util.PropertyPermission;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/*
 * Checkstyle complains about star imports,
 * but PMD JUnit ruleset doesn't verify non-static imports.
 * Checkstyle insists on only one assertion per test,
 * but PMD complains about too many methods. Argh.
 * Once we split CallerBasedSecurityManager, we can improve this.
 */
/**
 * Ensure, as much as possible, that the CallerBasedSecurityManager
 * algorithms are correct.
 *
 * @author Carl Antuar
 */
@SuppressWarnings({ "PMD.TooManyStaticImports", "PMD.TooManyMethods" })
public class CallerBasedSecurityManagerTest {

  /**
   * Wipe out any security manager configuration.
   */
  @After
  public final void tearDown() {
    System.setSecurityManager(null);
    System.clearProperty(CallerBasedSecurityManager.LOG_PROPERTY);
  }

  /**
   * Ignore standard Java APIs since they don't initiate actions.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public final void shouldDetectJavaAPIAsSystemClass() {
    checkSystemClass(Object.class, true);
  }

  /**
   * Ignore internal JVM classes since they are basically like the APIs.
   */
  @Test
  public final void shouldDetectJVMInternalClassAsSystemClass() {
    try {
      checkSystemClass(Class.forName("sun.misc.BASE64Decoder"), true);
    } catch (ClassNotFoundException e) {
      fail("Unknown JVM. Adapt the security manager before using it!");
    }
  }

  /**
   * Check a generic non-system class that we provide.
   */
  @SuppressWarnings("PMD.JUnitTestsShouldIncludeAssert")
  @Test
  public final void shouldDetectOrdinaryClassAsNonSystemClass() {
    checkSystemClass(getClass(), false);
  }

  /**
   * Helper for methods that test the 'isSystemClass' method.
   * @param clazz The class to check.
   * @param expectSystem Whether or not 'clazz'
   * should be treated as a system class.
   */
  private static void checkSystemClass(final Class clazz,
                                       final boolean expectSystem) {
    assertEquals(
      String.format("%s to be treated as system class:", clazz.getName()),
      expectSystem,
      CallerBasedSecurityManager.isSystemClass(clazz)
    );
  }

  /**
   * The last non-system caller, when we ask, should be ourselves.
   */
  @Test
  public final void shouldDetectLastNonSystemCaller() {
    final Class<?> manager = CallerBasedSecurityManager.class;
    final Class<?> test = CallerBasedSecurityManagerTest.class;
    final Class<?> system = Object.class;
    assertSame("Wrong caller identified",
      CallerBasedSecurityManager.getLastCaller(
        manager,
        manager,
        system,
        manager,
        test
      ),
      manager
    );
  }

  /**
   * Completely-privileged stacks should be ignored.
   */
  @Test
  public final void shouldReturnNullForAllSystemStack() {
    assertNull("No caller expected for all-system stack",
      CallerBasedSecurityManager.getLastCaller(
        Object.class,
        Object.class,
        Object.class
      )
    );
  }

  /**
   * Ensure that exception is thrown for permission we don't have.
   */
  @Test(expected = SecurityException.class)
  public final void shouldThrowSecurityExceptionForUnprivilegedCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "write");
    new CallerBasedSecurityManager().checkPermission(perm);
  }

  /**
   * Test policy permits reading system properties.
   */
  @Test
  public final void shouldNotThrowSecurityExceptionForPrivilegedCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "read");
    try {
      new CallerBasedSecurityManager().checkPermission(perm);
    } catch (SecurityException e) {
      fail("Expected permission " + perm + " to be granted");
    }
  }

  /**
   * Check the security bypass for privileged code.
   */
  @Test
  public final void shouldBypassSecurityToCheckPermissions() {
    System.setSecurityManager(new CallerBasedSecurityManager());
    assertFalse("Test should not have AllPermission",
      CallerBasedSecurityManager.implies(
        getClass(), CallerBasedSecurityManager.ALL_PERM
      )
    );
  }

  /**
   * Completely-privileged stacks should be ignored.
   */
  @Test
  public final void shouldNotThrowSecurityExceptionForSystemCode() {
    final Permission perm = new PropertyPermission("java.io.tmpdir", "read");
    try {
      new CallerBasedSecurityManager().checkPermission(
        new Class<?>[] {
          Object.class, Object.class, Object.class
        }
        , perm
      );
    } catch (SecurityException e) {
      fail("System code should be ignored");
    }
  }

  /**
   * Ensure no exception happens in log mode.
   * @exception UnsupportedEncodingException Should never happen for UTF-8.
   */
  @Test
  public final void shouldNotThrowSecurityExceptionInLogMode()
    throws UnsupportedEncodingException {
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    System.setErr(new PrintStream(baos, true, "UTF-8"));
    System.setProperty(CallerBasedSecurityManager.LOG_PROPERTY, "");
    new CallerBasedSecurityManager().checkPermission(new AllPermission());
    assertTrue("Expected permission to be logged",
      new String(baos.toByteArray(), "UTF-8")
        .contains(AllPermission.class.getName())
    );
  }

}
