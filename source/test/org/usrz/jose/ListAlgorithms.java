package org.usrz.jose;

import java.security.Provider;
import java.security.Security;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.testng.annotations.Test;


public class ListAlgorithms {

    @Test
    public void listAlgorithms() {
        for (Provider provider: Security.getProviders()) {

            System.err.println("PROVIDER \"" + provider.getName() + "\"");

            final Map<String, Set<String>> services = new TreeMap<>();
            provider.getServices().forEach((service) -> {
                final String type = service.getType();
                Set<String> algorithms = services.get(type);
                if (algorithms == null) {
                    algorithms = new TreeSet<>();
                    services.put(type, algorithms);
                }
                algorithms.add(service.getAlgorithm());
            });

            services.entrySet().forEach((service) -> {
                System.err.println("  TYPE \"" + service.getKey() + "\"");
                service.getValue().forEach((algorithm) -> {
                    System.err.println("        -> \"" + algorithm + "\"");
                });
            });
        }
    }
}
