package id.antuar.carl.security;

import java.security.AccessControlException;
import java.security.Permission;
import java.util.Arrays;
import java.util.Collection;

public class CallerBasedSecurityManager extends SecurityManager {

	private Collection<String> SYSTEM_PACKAGES = Arrays.asList("java.", "sun.");

	protected Class getLastNonSystemCaller() {
		Class[] callStack = getClassContext();
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
		Class clazz = getLastNonSystemCaller();
		if (clazz == null) {
			return;
		}
		if (!clazz.getProtectionDomain().implies(perm)) {
			throw new AccessControlException("access denied for "+clazz+": "+perm, perm);
		}
		System.out.println("DEBUG: granting "+perm+" to "+clazz);
	}
}
