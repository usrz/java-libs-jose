package org.usrz.jose.core;

import java.beans.ConstructorProperties;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.type.TypeFactory;

public abstract class BeanBuilder<T> implements Builder<T> {

    private static final TypeFactory TYPE_FACTORY = TypeFactory.defaultInstance();
    private static final ConcurrentMap<Entry<Class<?>, Class<?>>, Maker<?>> CACHE =
            new ConcurrentHashMap<>();

    private final Maker<T> beanConstructor;

    @SuppressWarnings({ "rawtypes", "unchecked" })
    protected BeanBuilder(final Class<? extends T> type) {
        final Class thisClass = this.getClass();

        final Entry cacheKey = new SimpleImmutableEntry(thisClass, type);

        this.beanConstructor = (Maker<T>) CACHE.computeIfAbsent(cacheKey, (key) -> {
            return new Maker(thisClass, type);
        });
    }

    public T build() {
        return beanConstructor.build(this);
    }

    private static class Maker<T> {

        private final Constructor<?> constructor;
        private final Field[] fields;

        public Maker(Class<? extends Builder<T>> builder, Class<? extends T> type) {

            Constructor<?> constructor = null;
            Field[] fields = null;

            for (Constructor<?> current: type.getDeclaredConstructors()) {
                if (current.isAnnotationPresent(ConstructorProperties.class)) {

                    if (constructor != null) {
                        throw new IllegalArgumentException("Multiple @ConstructorProperties annotated constructors in " + type.getName());
                    }

                    final String[] properties = current.getAnnotation(ConstructorProperties.class).value();
                    if (properties.length != current.getParameterCount()) {
                        throw new IllegalArgumentException("Constructor parameters and @ConstructorProperties value differ in " + type.getName());
                    }

                    fields = new Field[properties.length];
                    current.setAccessible(true);
                    constructor = current;

                    final Type[] parameters = current.getGenericParameterTypes();
                    for (int x = 0; x < properties.length; x ++) {
                        final Field field = findField(properties[x], builder);

                        final JavaType parameterType = TYPE_FACTORY.constructType(current.getGenericParameterTypes()[x], type);
                        final JavaType fieldType = TYPE_FACTORY.constructType(field.getGenericType(), builder);

                        if (TYPE_FACTORY.moreSpecificType(fieldType, parameterType).equals(parameterType)) {
                            field.setAccessible(true);
                            fields[x] = field;
                            continue;
                        } else {
                            throw new IllegalArgumentException("Builder " + builder.getName() + " field " + properties[x] +
                                          " of type " + field.getType().getName() + " is not assignable from constructor " +
                                          "parameter " + x + " of type " + parameters[x] + " in " + type.getName());
                        }
                    }
                }
            }

            if ((constructor == null) || (fields == null)) {
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
        public T build(Builder<T> builder) {
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
}
