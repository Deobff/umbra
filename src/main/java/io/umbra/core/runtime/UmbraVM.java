package io.umbra.core.runtime;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal stack-machine interpreter used by virtualized methods.
 *
 * <p>This class is injected into the protected program; it must only depend on
 * the JDK. Values are boxed in {@code Object} form. The supported opcode subset
 * is produced by {@code VirtualizationPass}. Opcodes use the JVM numbering;
 * operands follow the opcode in the {@code code} array. Method, field and type
 * references are strings ({@code "M|owner|name|desc"}, {@code "F|owner|name|desc"},
 * {@code "T|descriptor"}) stored in the {@code refs} array.</p>
 *
 * <p>Virtual calls are resolved through reflection on the static owner type and
 * still dispatch to overrides. This class is not intended to be used directly;
 * it is remapped and injected into the output JAR.</p>
 */
public final class UmbraVM {

    private static final Map<String, Field> FIELDS = new ConcurrentHashMap<String, Field>();
    private static final Map<String, Method> METHODS = new ConcurrentHashMap<String, Method>();
    private static final Map<String, Class<?>> TYPES = new ConcurrentHashMap<String, Class<?>>();

    private UmbraVM() {
    }

    /**
     * Executes one virtualized method body.
     *
     * @param code      bytecode in the reduced instruction set
     * @param constants constant pool (boxed values and class literals)
     * @param refs      method/field/type references
     * @param locals    local variable slots; slot 0 holds {@code this} for instance methods
     * @return the boxed return value, or {@code null} for {@code void}
     */
    public static Object run(int[] code, Object[] constants, String[] refs, Object[] locals) {
        Object[] stack = new Object[Math.max(32, Math.min(512, code.length + 8))];
        int sp = 0;
        int pc = 0;
        while (true) {
            if (sp + 2 > stack.length) {
                Object[] grown = new Object[stack.length * 2];
                System.arraycopy(stack, 0, grown, 0, stack.length);
                stack = grown;
            }
            int op = code[pc++];
            switch (op) {
                case 0: // NOP
                    break;
                case 1: // ACONST_NULL
                    stack[sp++] = null;
                    break;
                case 2: // ICONST_M1
                case 3: case 4: case 5: case 6: case 7: case 8: // ICONST_0 .. ICONST_5
                    stack[sp++] = Integer.valueOf(op - 3);
                    break;
                case 9: // LCONST_0
                case 10: // LCONST_1
                    stack[sp++] = Long.valueOf(op - 9);
                    break;
                case 11: // FCONST_0
                case 12: // FCONST_1
                case 13: // FCONST_2
                    stack[sp++] = Float.valueOf(op - 11);
                    break;
                case 14: // DCONST_0
                case 15: // DCONST_1
                    stack[sp++] = Double.valueOf(op - 14);
                    break;
                case 16: // BIPUSH
                    stack[sp++] = Integer.valueOf(code[pc++]);
                    break;
                case 17: // SIPUSH
                    stack[sp++] = Integer.valueOf(code[pc++]);
                    break;
                case 18: { // LDC
                    Object constant = constants[code[pc++]];
                    if (constant instanceof String[]) {
                        // Lazy class constant marker { "C", descriptor }: resolved
                        // here (at first execution) through the context class
                        // loader chain instead of eagerly in the holder <clinit>,
                        // because program classes may live in a nested container.
                        String[] marker = (String[]) constant;
                        if (marker.length == 2 && "C".equals(marker[0])) {
                            constant = type(marker[1]);
                        }
                    }
                    stack[sp++] = constant;
                    break;
                }
                case 21: case 22: case 23: case 24: case 25: // ILOAD..ALOAD
                    stack[sp++] = locals[code[pc++]];
                    break;
                case 46: case 47: case 48: case 49: case 50: case 51: case 52: case 53: {
                    int index = i(stack[--sp]);
                    Object array = stack[--sp];
                    stack[sp++] = arrayLoad(array, index, op);
                    break;
                }
                case 54: case 55: case 56: case 57: case 58: // ISTORE..ASTORE
                    locals[code[pc++]] = stack[--sp];
                    break;
                case 79: case 80: case 81: case 82: case 83: case 84: case 85: case 86: {
                    Object value = stack[--sp];
                    int index = i(stack[--sp]);
                    Object array = stack[--sp];
                    arrayStore(array, index, value, op);
                    break;
                }
                case 87: // POP
                    sp--;
                    break;
                case 88: // POP2
                    sp -= isWide(stack[sp - 1]) ? 1 : 2;
                    break;
                case 89: // DUP
                    stack[sp] = stack[sp - 1];
                    sp++;
                    break;
                case 90: { // DUP_X1
                    Object v1 = stack[sp - 1];
                    Object v2 = stack[sp - 2];
                    stack[sp] = v1;
                    stack[sp - 1] = v2;
                    stack[sp - 2] = v1;
                    sp++;
                    break;
                }
                case 91: { // DUP_X2
                    Object v1 = stack[sp - 1];
                    if (isWide(stack[sp - 2])) {
                        Object v2 = stack[sp - 2];
                        stack[sp - 2] = v1;
                        stack[sp - 1] = v2;
                        stack[sp] = v1;
                    } else {
                        Object v2 = stack[sp - 2];
                        Object v3 = stack[sp - 3];
                        stack[sp - 3] = v1;
                        stack[sp - 2] = v3;
                        stack[sp - 1] = v2;
                        stack[sp] = v1;
                    }
                    sp++;
                    break;
                }
                case 92: // DUP2
                    if (isWide(stack[sp - 1])) {
                        stack[sp] = stack[sp - 1];
                        sp++;
                    } else {
                        stack[sp] = stack[sp - 2];
                        stack[sp + 1] = stack[sp - 1];
                        sp += 2;
                    }
                    break;
                case 93: { // DUP2_X1
                    if (isWide(stack[sp - 1])) {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        stack[sp - 2] = v1;
                        stack[sp - 1] = v2;
                        stack[sp] = v1;
                        sp++;
                    } else {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        Object v3 = stack[sp - 3];
                        stack[sp - 3] = v2;
                        stack[sp - 2] = v1;
                        stack[sp - 1] = v3;
                        stack[sp] = v2;
                        stack[sp + 1] = v1;
                        sp += 2;
                    }
                    break;
                }
                case 94: { // DUP2_X2
                    if (isWide(stack[sp - 1]) && isWide(stack[sp - 2])) {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        stack[sp - 2] = v1;
                        stack[sp - 1] = v2;
                        stack[sp] = v1;
                        sp++;
                    } else if (isWide(stack[sp - 1])) {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        Object v3 = stack[sp - 3];
                        stack[sp - 3] = v1;
                        stack[sp - 2] = v3;
                        stack[sp - 1] = v2;
                        stack[sp] = v1;
                        sp++;
                    } else if (isWide(stack[sp - 3])) {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        Object v3 = stack[sp - 3];
                        stack[sp - 3] = v2;
                        stack[sp - 2] = v1;
                        stack[sp - 1] = v3;
                        stack[sp] = v2;
                        stack[sp + 1] = v1;
                        sp += 2;
                    } else {
                        Object v1 = stack[sp - 1];
                        Object v2 = stack[sp - 2];
                        Object v3 = stack[sp - 3];
                        Object v4 = stack[sp - 4];
                        stack[sp - 4] = v2;
                        stack[sp - 3] = v1;
                        stack[sp - 2] = v4;
                        stack[sp - 1] = v3;
                        stack[sp] = v2;
                        stack[sp + 1] = v1;
                        sp += 2;
                    }
                    break;
                }
                case 95: { // SWAP
                    Object value = stack[sp - 1];
                    stack[sp - 1] = stack[sp - 2];
                    stack[sp - 2] = value;
                    break;
                }
                case 96: stack[sp - 2] = boxI(i(stack[sp - 2]) + i(stack[sp - 1])); sp--; break;
                case 97: stack[sp - 2] = boxL(l(stack[sp - 2]) + l(stack[sp - 1])); sp--; break;
                case 98: stack[sp - 2] = boxF(f(stack[sp - 2]) + f(stack[sp - 1])); sp--; break;
                case 99: stack[sp - 2] = boxD(d(stack[sp - 2]) + d(stack[sp - 1])); sp--; break;
                case 100: stack[sp - 2] = boxI(i(stack[sp - 2]) - i(stack[sp - 1])); sp--; break;
                case 101: stack[sp - 2] = boxL(l(stack[sp - 2]) - l(stack[sp - 1])); sp--; break;
                case 102: stack[sp - 2] = boxF(f(stack[sp - 2]) - f(stack[sp - 1])); sp--; break;
                case 103: stack[sp - 2] = boxD(d(stack[sp - 2]) - d(stack[sp - 1])); sp--; break;
                case 104: stack[sp - 2] = boxI(i(stack[sp - 2]) * i(stack[sp - 1])); sp--; break;
                case 105: stack[sp - 2] = boxL(l(stack[sp - 2]) * l(stack[sp - 1])); sp--; break;
                case 106: stack[sp - 2] = boxF(f(stack[sp - 2]) * f(stack[sp - 1])); sp--; break;
                case 107: stack[sp - 2] = boxD(d(stack[sp - 2]) * d(stack[sp - 1])); sp--; break;
                case 108: stack[sp - 2] = boxI(i(stack[sp - 2]) / i(stack[sp - 1])); sp--; break;
                case 109: stack[sp - 2] = boxL(l(stack[sp - 2]) / l(stack[sp - 1])); sp--; break;
                case 110: stack[sp - 2] = boxF(f(stack[sp - 2]) / f(stack[sp - 1])); sp--; break;
                case 111: stack[sp - 2] = boxD(d(stack[sp - 2]) / d(stack[sp - 1])); sp--; break;
                case 112: stack[sp - 2] = boxI(i(stack[sp - 2]) % i(stack[sp - 1])); sp--; break;
                case 113: stack[sp - 2] = boxL(l(stack[sp - 2]) % l(stack[sp - 1])); sp--; break;
                case 114: stack[sp - 2] = boxF(f(stack[sp - 2]) % f(stack[sp - 1])); sp--; break;
                case 115: stack[sp - 2] = boxD(d(stack[sp - 2]) % d(stack[sp - 1])); sp--; break;
                case 116: stack[sp - 1] = boxI(-i(stack[sp - 1])); break;
                case 117: stack[sp - 1] = boxL(-l(stack[sp - 1])); break;
                case 118: stack[sp - 1] = boxF(-f(stack[sp - 1])); break;
                case 119: stack[sp - 1] = boxD(-d(stack[sp - 1])); break;
                case 120: stack[sp - 2] = boxI(i(stack[sp - 2]) << i(stack[sp - 1])); sp--; break;
                case 121: stack[sp - 2] = boxL(l(stack[sp - 2]) << i(stack[sp - 1])); sp--; break;
                case 122: stack[sp - 2] = boxI(i(stack[sp - 2]) >> i(stack[sp - 1])); sp--; break;
                case 123: stack[sp - 2] = boxL(l(stack[sp - 2]) >> i(stack[sp - 1])); sp--; break;
                case 124: stack[sp - 2] = boxI(i(stack[sp - 2]) >>> i(stack[sp - 1])); sp--; break;
                case 125: stack[sp - 2] = boxL(l(stack[sp - 2]) >>> i(stack[sp - 1])); sp--; break;
                case 126: stack[sp - 2] = boxI(i(stack[sp - 2]) & i(stack[sp - 1])); sp--; break;
                case 127: stack[sp - 2] = boxL(l(stack[sp - 2]) & l(stack[sp - 1])); sp--; break;
                case 128: stack[sp - 2] = boxI(i(stack[sp - 2]) | i(stack[sp - 1])); sp--; break;
                case 129: stack[sp - 2] = boxL(l(stack[sp - 2]) | l(stack[sp - 1])); sp--; break;
                case 130: stack[sp - 2] = boxI(i(stack[sp - 2]) ^ i(stack[sp - 1])); sp--; break;
                case 131: stack[sp - 2] = boxL(l(stack[sp - 2]) ^ l(stack[sp - 1])); sp--; break;
                case 132: { // IINC
                    int slot = code[pc++];
                    int delta = code[pc++];
                    locals[slot] = boxI(i(locals[slot]) + delta);
                    break;
                }
                case 133: stack[sp - 1] = boxL(i(stack[sp - 1])); break;
                case 134: stack[sp - 1] = boxF(i(stack[sp - 1])); break;
                case 135: stack[sp - 1] = boxD(i(stack[sp - 1])); break;
                case 136: stack[sp - 1] = boxI((int) l(stack[sp - 1])); break;
                case 137: stack[sp - 1] = boxF((float) l(stack[sp - 1])); break;
                case 138: stack[sp - 1] = boxD((double) l(stack[sp - 1])); break;
                case 139: stack[sp - 1] = boxI((int) f(stack[sp - 1])); break;
                case 140: stack[sp - 1] = boxL((long) f(stack[sp - 1])); break;
                case 141: stack[sp - 1] = boxD((double) f(stack[sp - 1])); break;
                case 142: stack[sp - 1] = boxI((int) d(stack[sp - 1])); break;
                case 143: stack[sp - 1] = boxL((long) d(stack[sp - 1])); break;
                case 144: stack[sp - 1] = boxF((float) d(stack[sp - 1])); break;
                case 145: stack[sp - 1] = boxI((byte) i(stack[sp - 1])); break;
                case 146: stack[sp - 1] = boxI((char) i(stack[sp - 1])); break;
                case 147: stack[sp - 1] = boxI((short) i(stack[sp - 1])); break;
                case 148: stack[sp - 2] = boxI(Long.compare(l(stack[sp - 2]), l(stack[sp - 1]))); sp--; break;
                case 149: { // FCMPL: NaN -> -1
                    float a = f(stack[sp - 2]);
                    float b = f(stack[sp - 1]);
                    stack[sp - 2] = boxI(Float.isNaN(a) || Float.isNaN(b) ? -1 : (a == b ? 0 : (a < b ? -1 : 1)));
                    sp--;
                    break;
                }
                case 150: { // FCMPG: NaN -> 1
                    float a = f(stack[sp - 2]);
                    float b = f(stack[sp - 1]);
                    stack[sp - 2] = boxI(Float.isNaN(a) || Float.isNaN(b) ? 1 : (a == b ? 0 : (a < b ? -1 : 1)));
                    sp--;
                    break;
                }
                case 151: { // DCMPL: NaN -> -1
                    double a = d(stack[sp - 2]);
                    double b = d(stack[sp - 1]);
                    stack[sp - 2] = boxI(Double.isNaN(a) || Double.isNaN(b) ? -1 : (a == b ? 0 : (a < b ? -1 : 1)));
                    sp--;
                    break;
                }
                case 152: { // DCMPG: NaN -> 1
                    double a = d(stack[sp - 2]);
                    double b = d(stack[sp - 1]);
                    stack[sp - 2] = boxI(Double.isNaN(a) || Double.isNaN(b) ? 1 : (a == b ? 0 : (a < b ? -1 : 1)));
                    sp--;
                    break;
                }
                case 153: if (i(stack[--sp]) == 0) pc = code[pc]; else pc++; break;
                case 154: if (i(stack[--sp]) != 0) pc = code[pc]; else pc++; break;
                case 155: if (i(stack[--sp]) < 0) pc = code[pc]; else pc++; break;
                case 156: if (i(stack[--sp]) >= 0) pc = code[pc]; else pc++; break;
                case 157: if (i(stack[--sp]) > 0) pc = code[pc]; else pc++; break;
                case 158: if (i(stack[--sp]) <= 0) pc = code[pc]; else pc++; break;
                case 159: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a == b) pc = code[pc]; else pc++; break; }
                case 160: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a != b) pc = code[pc]; else pc++; break; }
                case 161: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a < b) pc = code[pc]; else pc++; break; }
                case 162: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a >= b) pc = code[pc]; else pc++; break; }
                case 163: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a > b) pc = code[pc]; else pc++; break; }
                case 164: { int b = i(stack[--sp]); int a = i(stack[--sp]); if (a <= b) pc = code[pc]; else pc++; break; }
                case 165: { Object b = stack[--sp]; Object a = stack[--sp]; if (a == b) pc = code[pc]; else pc++; break; }
                case 166: { Object b = stack[--sp]; Object a = stack[--sp]; if (a != b) pc = code[pc]; else pc++; break; }
                case 167: pc = code[pc]; break;
                case 170: { // TABLESWITCH
                    int defaultPc = code[pc++];
                    int low = code[pc++];
                    int high = code[pc++];
                    int key = i(stack[--sp]);
                    if (key < low || key > high) {
                        pc = defaultPc;
                    } else {
                        pc = code[pc + (key - low)];
                    }
                    break;
                }
                case 171: { // LOOKUPSWITCH
                    int defaultPc = code[pc++];
                    int pairs = code[pc++];
                    int key = i(stack[--sp]);
                    int target = defaultPc;
                    for (int i = 0; i < pairs; i++) {
                        int match = code[pc++];
                        int label = code[pc++];
                        if (match == key) {
                            target = label;
                            break;
                        }
                    }
                    pc = target;
                    break;
                }
                case 172: case 173: case 174: case 175: case 176: // xRETURN
                    return stack[--sp];
                case 177: // RETURN
                    return null;
                case 178: // GETSTATIC
                    stack[sp++] = fieldValue(refs[code[pc++]], null);
                    break;
                case 179: // PUTSTATIC
                    setField(refs[code[pc++]], null, stack[--sp]);
                    break;
                case 180: { // GETFIELD
                    Object receiver = stack[--sp];
                    stack[sp++] = fieldValue(refs[code[pc++]], receiver);
                    break;
                }
                case 181: { // PUTFIELD
                    Object value = stack[--sp];
                    Object receiver = stack[--sp];
                    setField(refs[code[pc++]], receiver, value);
                    break;
                }
                case 182: case 183: case 184: case 185:
                    sp = invoke(refs[code[pc++]], stack, sp, op);
                    break;
                case 187:
                    throw new IllegalStateException("NEW is not supported by the Umbra VM");
                case 188: { // NEWARRAY
                    int type = code[pc++];
                    int length = i(stack[--sp]);
                    stack[sp++] = newArray(type, length);
                    break;
                }
                case 189: { // ANEWARRAY
                    String desc = typeDescriptor(refs[code[pc++]]);
                    int length = i(stack[--sp]);
                    stack[sp++] = Array.newInstance(type(desc), length);
                    break;
                }
                case 190: { // ARRAYLENGTH
                    Object array = stack[sp - 1];
                    stack[sp - 1] = boxI(Array.getLength(array));
                    break;
                }
                case 191: { // ATHROW
                    Throwable throwable = (Throwable) stack[--sp];
                    sneakyThrow(throwable);
                    break;
                }
                case 192: { // CHECKCAST
                    String desc = typeDescriptor(refs[code[pc++]]);
                    Object value = stack[sp - 1];
                    if (value != null && !type(desc).isInstance(value)) {
                        throw new ClassCastException(value.getClass().getName() + " cannot be cast to " + desc);
                    }
                    break;
                }
                case 193: { // INSTANCEOF
                    String desc = typeDescriptor(refs[code[pc++]]);
                    Object value = stack[--sp];
                    stack[sp++] = boxI(type(desc).isInstance(value) ? 1 : 0);
                    break;
                }
                case 194:
                case 195:
                    throw new IllegalStateException("monitor instructions are not supported by the Umbra VM");
                case 197: { // MULTIANEWARRAY
                    String desc = typeDescriptor(refs[code[pc++]]);
                    int dims = code[pc++];
                    int[] sizes = new int[dims];
                    for (int i = dims - 1; i >= 0; i--) {
                        sizes[i] = i(stack[--sp]);
                    }
                    stack[sp++] = Array.newInstance(elementType(desc), sizes);
                    break;
                }
                case 198: { // IFNULL
                    if (stack[--sp] == null) pc = code[pc]; else pc++;
                    break;
                }
                case 199: { // IFNONNULL
                    if (stack[--sp] != null) pc = code[pc]; else pc++;
                    break;
                }
                default:
                    throw new IllegalStateException("Unsupported VM opcode " + op);
            }
        }
    }

    private static int invoke(String ref, Object[] stack, int sp, int op) {
        String[] parts = splitRef(ref);
        String owner = parts[1];
        String name = parts[2];
        String desc = parts[3];
        Class<?> ownerType = type(owner);
        Class<?>[] types = parameterTypes(desc);
        Method method = method(ownerType, name, desc, op);
        Object[] args = new Object[types.length];
        int base = sp;
        for (int i = types.length - 1; i >= 0; i--) {
            args[i] = coerce(types[i], stack[--base]);
        }
        Object receiver = op == 184 ? null : stack[--base];
        // Array clone() is a JVM intrinsic, not a reflectively invokable method:
        // on JDK 9+ Object.clone is inaccessible from an unnamed module, so it
        // is emulated with an explicit copy.
        if (receiver != null && receiver.getClass().isArray() && "clone".equals(name)
                && types.length == 0) {
            Object copy = arrayClone(receiver);
            if (!voidReturn(desc)) {
                stack[base++] = coerceReturn(desc, copy);
            }
            return base;
        }
        try {
            Object result = method.invoke(receiver, args);
            if (!voidReturn(desc)) {
                stack[base++] = coerceReturn(desc, result);
            }
            return base;
        } catch (InvocationTargetException e) {
            sneakyThrow(e.getCause());
            return base;
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Umbra VM cannot access " + ref, e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Umbra VM argument mismatch for " + ref, e);
        }
    }

    private static Method method(Class<?> owner, String name, String desc, int op) {
        String key = (op == 183 || op == 184 ? "S|" : "V|") + owner.getName() + "|" + name + "|" + desc;
        Method method = METHODS.get(key);
        if (method != null) {
            return method;
        }
        Class<?>[] parameters = parameterTypes(desc);
        try {
            if (op == 182 || op == 185) {
                // Use the static owner type so reflection keeps normal virtual
                // dispatch, and so non-public implementation classes work.
                method = owner.getMethod(name, parameters);
            } else {
                method = findDeclared(owner, name, parameters);
            }
        } catch (NoSuchMethodException e) {
            method = findDeclared(owner, name, parameters);
        }
        if (method == null) {
            throw new IllegalStateException("Umbra VM cannot resolve " + name + desc + " on " + owner.getName());
        }
        makeAccessible(method);
        METHODS.put(key, method);
        return method;
    }

    private static Method findDeclared(Class<?> type, String name, Class<?>[] parameters) {
        for (Class<?> current = type; current != null; current = current.getSuperclass()) {
            try {
                return current.getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                // continue
            }
            Method fromInterface = findInInterfaces(current, name, parameters);
            if (fromInterface != null) {
                return fromInterface;
            }
        }
        return null;
    }

    private static Method findInInterfaces(Class<?> type, String name, Class<?>[] parameters) {
        for (Class<?> itf : type.getInterfaces()) {
            try {
                return itf.getDeclaredMethod(name, parameters);
            } catch (NoSuchMethodException ignored) {
                // continue
            }
            Method nested = findInInterfaces(itf, name, parameters);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    private static boolean voidReturn(String descriptor) {
        return descriptor.charAt(descriptor.indexOf(')') + 1) == 'V';
    }

    private static Object coerceReturn(String descriptor, Object value) {
        if (value == null) {
            return null;
        }
        char sort = descriptor.charAt(descriptor.indexOf(')') + 1);
        switch (sort) {
            case 'Z': return boxI(asInt(value) != 0 ? 1 : 0);
            case 'B': return boxI((byte) asInt(value));
            case 'C': return boxI((char) asInt(value));
            case 'S': return boxI((short) asInt(value));
            case 'J': return boxL(asLong(value));
            case 'F': return boxF(asFloat(value));
            case 'D': return boxD(asDouble(value));
            case 'I': return boxI(asInt(value));
            default: return value;
        }
    }

    /**
     * Converts a stack value to the parameter type of a reflective call.
     *
     * <p>Values can be boxed as {@code Boolean}, {@code Character} or any
     * {@code Number}; a plain {@code (Number)} cast is therefore wrong and used
     * to abort with {@code ClassCastException} inside virtualized code.</p>
     */
    private static Object coerce(Class<?> target, Object value) {
        if (target == boolean.class) {
            if (value instanceof Boolean) {
                return value;
            }
            return Boolean.valueOf(asInt(value) != 0);
        }
        if (target == byte.class) {
            return Byte.valueOf((byte) asInt(value));
        }
        if (target == char.class) {
            return Character.valueOf((char) asInt(value));
        }
        if (target == short.class) {
            return Short.valueOf((short) asInt(value));
        }
        if (target == int.class) {
            return Integer.valueOf(asInt(value));
        }
        if (target == long.class) {
            return Long.valueOf(asLong(value));
        }
        if (target == float.class) {
            return Float.valueOf(asFloat(value));
        }
        if (target == double.class) {
            return Double.valueOf(asDouble(value));
        }
        return value;
    }

    /** Unboxes any numeric/boolean/character representation to an int. */
    private static int asInt(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1 : 0;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        if (value == null) {
            return 0;
        }
        return ((Number) value).intValue();
    }

    private static long asLong(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1L : 0L;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        if (value == null) {
            return 0L;
        }
        return ((Number) value).longValue();
    }

    private static float asFloat(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1f : 0f;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        if (value == null) {
            return 0f;
        }
        return ((Number) value).floatValue();
    }

    private static double asDouble(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1d : 0d;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        if (value == null) {
            return 0d;
        }
        return ((Number) value).doubleValue();
    }

    private static String typeDescriptor(String ref) {
        return ref.startsWith("T|") ? ref.substring(2) : ref;
    }

    private static String[] splitRef(String ref) {
        String[] parts = ref.split("\\|", 4);
        if (parts.length < 4) {
            throw new IllegalStateException("Malformed Umbra VM reference: " + ref);
        }
        return parts;
    }

    private static Object fieldValue(String ref, Object receiver) {
        Field field = field(ref);
        try {
            return coerceReturn(field.getType() == boolean.class ? "()Z" : "()" + descriptor(field.getType()),
                    field.get(receiver));
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Umbra VM cannot read " + ref, e);
        }
    }

    private static void setField(String ref, Object receiver, Object value) {
        Field field = field(ref);
        try {
            field.set(receiver, coerce(field.getType(), value));
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Umbra VM cannot write " + ref, e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Umbra VM type mismatch for " + ref, e);
        }
    }

    private static Field field(String ref) {
        Field field = FIELDS.get(ref);
        if (field != null) {
            return field;
        }
        String[] parts = splitRef(ref);
        Class<?> owner = type(parts[1]);
        String name = parts[2];
        try {
            for (Class<?> current = owner; current != null; current = current.getSuperclass()) {
                try {
                    field = current.getDeclaredField(name);
                    break;
                } catch (NoSuchFieldException ignored) {
                    // continue
                }
            }
            if (field == null) {
                field = findInterfaceField(owner, name);
            }
            if (field == null) {
                throw new IllegalStateException("Umbra VM cannot resolve field " + name + " on " + owner.getName());
            }
            makeAccessible(field);
            FIELDS.put(ref, field);
            return field;
        } catch (RuntimeException e) {
            throw e;
        }
    }

    private static Field findInterfaceField(Class<?> type, String name) {
        for (Class<?> itf : type.getInterfaces()) {
            try {
                return itf.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                // continue
            }
            Field nested = findInterfaceField(itf, name);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    private static String descriptor(Class<?> type) {
        if (type.isArray()) {
            return type.getName().replace('.', '/');
        }
        if (type == boolean.class) {
            return "Z";
        }
        if (type == byte.class) {
            return "B";
        }
        if (type == char.class) {
            return "C";
        }
        if (type == short.class) {
            return "S";
        }
        if (type == int.class) {
            return "I";
        }
        if (type == long.class) {
            return "J";
        }
        if (type == float.class) {
            return "F";
        }
        if (type == double.class) {
            return "D";
        }
        return "L" + type.getName().replace('.', '/') + ";";
    }

    private static void makeAccessible(AccessibleObject object) {
        try {
            object.setAccessible(true);
        } catch (RuntimeException ignored) {
            // Public members in exported packages remain callable without it.
        }
    }

    /**
     * Loads a class through the context loader first (nested JAR/WAR containers
     * install their own loader there), then the helper's loader and the system
     * loader. See the equivalent helper in {@code UmbraVM2}.
     */
    private static Class<?> forName(String dottedName) throws ClassNotFoundException {
        ClassNotFoundException failure = null;
        ClassLoader context = null;
        try {
            context = Thread.currentThread().getContextClassLoader();
        } catch (RuntimeException ignored) {
            context = null;
        }
        if (context != null) {
            try {
                return Class.forName(dottedName, false, context);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader own = UmbraVM.class.getClassLoader();
        if (own != null && own != context) {
            try {
                return Class.forName(dottedName, false, own);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        ClassLoader system = ClassLoader.getSystemClassLoader();
        if (system != null && system != own && system != context) {
            try {
                return Class.forName(dottedName, false, system);
            } catch (ClassNotFoundException e) {
                failure = e;
            }
        }
        throw failure == null ? new ClassNotFoundException(dottedName) : failure;
    }

    private static Class<?> type(String descriptor) {
        Class<?> type = TYPES.get(descriptor);
        if (type != null) {
            return type;
        }
        try {
            if (descriptor.startsWith("[")) {
                type = forName(descriptor.replace('/', '.'));
            } else if ("Z".equals(descriptor)) {
                type = boolean.class;
            } else if ("B".equals(descriptor)) {
                type = byte.class;
            } else if ("C".equals(descriptor)) {
                type = char.class;
            } else if ("S".equals(descriptor)) {
                type = short.class;
            } else if ("I".equals(descriptor)) {
                type = int.class;
            } else if ("J".equals(descriptor)) {
                type = long.class;
            } else if ("F".equals(descriptor)) {
                type = float.class;
            } else if ("D".equals(descriptor)) {
                type = double.class;
            } else if ("V".equals(descriptor)) {
                type = void.class;
            } else if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
                type = forName(descriptor.substring(1, descriptor.length() - 1).replace('/', '.'));
            } else {
                type = forName(descriptor.replace('/', '.'));
            }
            TYPES.put(descriptor, type);
            return type;
        } catch (Exception e) {
            throw new RuntimeException("Umbra VM cannot load type " + descriptor, e);
        }
    }

    private static Class<?> elementType(String descriptor) {
        int index = 0;
        while (index < descriptor.length() && descriptor.charAt(index) == '[') {
            index++;
        }
        return type(descriptor.substring(index));
    }

    private static Class<?>[] parameterTypes(String descriptor) {
        List<Class<?>> out = new ArrayList<Class<?>>();
        int i = 1;
        while (descriptor.charAt(i) != ')') {
            int start = i;
            while (descriptor.charAt(i) == '[') {
                i++;
            }
            if (descriptor.charAt(i) == 'L') {
                i = descriptor.indexOf(';', i) + 1;
            } else {
                i++;
            }
            out.add(type(descriptor.substring(start, i)));
        }
        return out.toArray(new Class<?>[0]);
    }

    private static Object newArray(int type, int length) {
        switch (type) {
            case 4: return new boolean[length];
            case 5: return new char[length];
            case 6: return new float[length];
            case 7: return new double[length];
            case 8: return new byte[length];
            case 9: return new short[length];
            case 10: return new int[length];
            case 11: return new long[length];
            default: throw new IllegalStateException("Unsupported NEWARRAY type " + type);
        }
    }

    /** Emulates the JVM's array clone intrinsic (also works on JDK 9+). */
    private static Object arrayClone(Object array) {
        int length = Array.getLength(array);
        Object copy = Array.newInstance(array.getClass().getComponentType(), length);
        System.arraycopy(array, 0, copy, 0, length);
        return copy;
    }

    private static Object arrayLoad(Object array, int index, int op) {
        switch (op) {
            case 46: return boxI(Array.getInt(array, index));
            case 47: return boxL(Array.getLong(array, index));
            case 48: return boxF(Array.getFloat(array, index));
            case 49: return boxD(Array.getDouble(array, index));
            case 50: return Array.get(array, index);
            case 51:
                if (array instanceof boolean[]) {
                    return boxI(Array.getBoolean(array, index) ? 1 : 0);
                }
                return boxI(Array.getByte(array, index));
            case 52: return boxI(Array.getChar(array, index));
            case 53: return boxI(Array.getShort(array, index));
            default: throw new IllegalStateException("Unsupported array load " + op);
        }
    }

    private static void arrayStore(Object array, int index, Object value, int op) {
        switch (op) {
            case 79: Array.setInt(array, index, i(value)); return;
            case 80: Array.setLong(array, index, l(value)); return;
            case 81: Array.setFloat(array, index, f(value)); return;
            case 82: Array.setDouble(array, index, d(value)); return;
            case 83: Array.set(array, index, value); return;
            case 84:
                if (array instanceof boolean[]) {
                    Array.setBoolean(array, index, i(value) != 0);
                } else {
                    Array.setByte(array, index, (byte) i(value));
                }
                return;
            case 85: Array.setChar(array, index, (char) i(value)); return;
            case 86: Array.setShort(array, index, (short) i(value)); return;
            default: throw new IllegalStateException("Unsupported array store " + op);
        }
    }

    private static boolean isWide(Object value) {
        return value instanceof Long || value instanceof Double;
    }

    /*
     * The interpreter represents JVM boolean values as Integer 0/1 (JVM stack
     * convention). Older payloads and reflection results may still hand us a
     * java.lang.Boolean or java.lang.Character, so every numeric unboxing path
     * must accept those boxed types as well; a bare (Number) cast aborts with
     * ClassCastException inside virtualized code.
     */
    private static int i(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1 : 0;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).intValue();
    }

    private static long l(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1L : 0L;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).longValue();
    }

    private static float f(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1f : 0f;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).floatValue();
    }

    private static double d(Object value) {
        if (value instanceof Boolean) {
            return ((Boolean) value).booleanValue() ? 1d : 0d;
        }
        if (value instanceof Character) {
            return ((Character) value).charValue();
        }
        return ((Number) value).doubleValue();
    }
    private static Object boxI(int value) { return Integer.valueOf(value); }
    private static Object boxL(long value) { return Long.valueOf(value); }
    private static Object boxF(float value) { return Float.valueOf(value); }
    private static Object boxD(double value) { return Double.valueOf(value); }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> void sneakyThrow(Throwable throwable) throws T {
        throw (T) throwable;
    }
}
