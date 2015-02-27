package org.usrz.jose.core;

import java.beans.ConstructorProperties;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;


public class BeanBuilder<B, T> {

    private final Constructor<?> constructor;
    private final Field[] fields;

    public BeanBuilder(Class<? extends B> builder, Class<? extends T> type) {

        Constructor<?> constructor = null;
        Field[] fields = null;

        for (Constructor<?> c: type.getDeclaredConstructors()) {
            if (c.isAnnotationPresent(ConstructorProperties.class)) {

                if (constructor != null) {
                    throw new IllegalArgumentException("Multiple @ConstructorProperties annotated constructors");
                }

                final String[] properties = c.getAnnotation(ConstructorProperties.class).value();
                if (properties.length != c.getParameterCount()) {
                    throw new IllegalArgumentException("Constructor parameters and @ConstructorProperties value differ");
                }

                fields = new Field[properties.length];
                c.setAccessible(true);
                constructor = c;

                final Class<?>[] parameters = c.getParameterTypes();
                for (int x = 0; x < properties.length; x ++) {
                    final Field field = findField(properties[x], builder);
                    if (parameters[x].isAssignableFrom(field.getType())) {
                        field.setAccessible(true);
                        fields[x] = field;
                        continue;
                    } else {
                        throw new IllegalArgumentException("Builder field " + properties[x] + " of type " +
                                      field.getType().getName() + " is not assignable from constructor " +
                                      "parameter " + x + " of type " + parameters[x]);
                    }
                }
            }
        }

        if (constructor == null) {
            throw new IllegalArgumentException("No constructor annotated with @ConstructorProperties");
        }

        this.constructor = constructor;
        this.fields = fields;
    }

    private final Field findField(String name, Class<?> type) {
        if (type == null) throw new IllegalArgumentException("Builder does not declare field " + name);
        try {
            return type.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            return findField(name, type.getSuperclass());
        }
    }

    @SuppressWarnings("unchecked")
    public T build(B builder) {
        final Object[] parameters = new Object[fields.length];
        for (int x = 0; x < fields.length; x ++) try {
            parameters[x] = fields[x].get(builder);
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException("Unable to access field " + fields[x].getName(), exception);
        }
        try {
            return (T) constructor.newInstance(parameters);
        } catch (InstantiationException exception) {
            throw new IllegalStateException("Unable to instantiate " + constructor.getDeclaringClass().getName(), exception);
        } catch (IllegalAccessException exception) {
            throw new IllegalStateException("Unable to access constructor on " + constructor.getDeclaringClass().getName(), exception);
        } catch (InvocationTargetException exception) {
            throw new IllegalStateException("Exception constructing " + constructor.getDeclaringClass().getName(), exception);
        }
    }


}
