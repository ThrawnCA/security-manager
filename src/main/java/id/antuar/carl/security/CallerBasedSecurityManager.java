package id.antuar.carl.security;

import java.security.AccessControlException;
import java.security.Permission;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.Collection;

public class CallerBasedSecurityManager extends SecurityManager {

	private static final boolean LOG_MODE = System.getProperty("java.security.manager.log_mode") != null;
	private static final String PERMISSION_FORMAT = "grant codeBase \"%s\" {\n  permission %s\n} // (%s)";

	private Collection<String> SYSTEM_PACKAGES = Arrays.asList("java.", "sun.");

	protected Class getLastNonSystemCaller(Class[] callStack) {
		for (Class clazz : callStack) {
			if (clazz == CallerBasedSecurityManager.class) {
				continue;
			}
			boolean system = false;
			for (String packagePrefix : SYSTEM_PACKAGES) {
				if (clazz.getName().startsWith(packagePrefix)) {
					system = true;
				}
			}
			if (!system) {
				//~ System.out.println("DEBUG: Found non-system call stack class: "+clazz);
				return clazz;
			}
		}
		//~ System.out.println("DEBUG: Call stack contained only system classes");
		return null;
	}

	public void checkPermission(Permission perm) {
		//~ System.out.println("DEBUG: Checking permission "+perm);
		Class[] callStack = getClassContext();
		for (int i = 1; i < callStack.length; i++) {
			if (callStack[i] == getClass()) {
				return;
			}
		}
		Class clazz = getLastNonSystemCaller(callStack);
		if (clazz == null) {
			return;
		}
		ProtectionDomain domain = clazz.getProtectionDomain();
		if (!domain.implies(perm)) {
			if (LOG_MODE) {
				System.err.println(String.format(PERMISSION_FORMAT, domain.getCodeSource().getLocation(), perm.toString().replace("\" \"", "\", \""), clazz.getName()));
			} else {
				throw new AccessControlException("access denied: "+perm, perm);
			}
		}
	}
}
