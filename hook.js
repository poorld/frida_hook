// 日志工具和常量
const Log = Java.use("android.util.Log");
const TAG = "[FRIDA_SCRIPT]";

const TYPE = {
    INTERDICT: 0, // 拦截并返回指定值
    PASS: 1       // 放行调用原方法
};

// 返回值构造器
const createResult = (type, obj = null) => ({ return_type: type, return_obj: obj });
const pass = () => createResult(TYPE.PASS);
const interdict = (obj) => createResult(TYPE.INTERDICT, obj);

// 日志函数
function LOG(message, { tag = TAG, level = 'log', subTag = '' } = {}) {
    const fullMessage = subTag ? `${subTag}: ${message}` : message;
    console[level](fullMessage);
    Log[level === 'error' ? 'e' : 'v'](tag, fullMessage);
}

function logArray(strArray) {
    strArray.forEach(str => LOG(str));
}

function printStackTrace(message = 'StackTrace') {
    const stack = Log.getStackTraceString(Java.use("java.lang.Throwable").$new());
    LOG(`${message}: ${stack}`, { level: 'log' });
}

// Hook 方法
function traceMethod(targetClassMethod, printStack = false) {
    const delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1) return;

    const targetClass = targetClassMethod.slice(0, delim);
    const targetMethod = targetClassMethod.slice(delim + 1);

    let hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        LOG(`Failed to load class ${targetClass}: ${e}`, { level: 'error' });
        return;
    }

    const method = hook[targetMethod];
    if (!method || !method.overloads) {
        LOG(`Method ${targetMethod} not found in ${targetClass}`, { level: 'warn' });
        return;
    }

    const overloadCount = method.overloads.length;
    if (overloadCount === 0) return;

    LOG(`Hooking ${targetClassMethod} with ${overloadCount} overloads`, { level: 'log' });

    method.overloads.forEach((overload, i) => {
        overload.implementation = function (...args) {
            if (printStack) printStackTrace(`Call to ${targetClassMethod}`);

            const log = {
                hookInfo: `${targetClassMethod} [overload ${i}]`,
                args: args.length ? `[${args.map(arg => arg?.toString() ?? 'null').join(', ')}]` : '[]'
            };

            let retval;
            try {
                retval = overload.apply(this, args);
                log.return = retval?.toString() ?? 'null';
            } catch (e) {
                LOG(`Error in ${targetClassMethod}: ${e}`, { level: 'error' });
            }

            LOG(JSON.stringify(log, null, 2));
            return retval;
        };
    });
}

// 去重函数
function uniqBy(array) {
    return [...new Set(array)];
}

// Hook 类
function traceClass(targetClass, ignoreMethod = null, printStack = false) {
    Java.perform(() => {
        let hook;
        try {
            hook = Java.use(targetClass);
        } catch (e) {
            LOG(`Failed to load class ${targetClass}: ${e}`, { level: 'error' });
            return;
        }

        let methods;
        try {
            methods = hook.class.getDeclaredMethods();
        } catch (e) {
            LOG(`Failed to get methods for ${targetClass}: ${e}`, { level: 'error' });
            return;
        }

        const parsedMethods = methods.map(method => 
            method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]
        );
        const uniqueMethods = uniqBy(parsedMethods);

        LOG(`All methods: ${parsedMethods.join(', ')}`, { subTag: 'Methods' });
        LOG(`Tracing ${targetClass} with ${uniqueMethods.length} unique methods`);

        uniqueMethods.forEach(method => {
            if (ignoreMethod === method) {
                LOG(`Ignoring method: ${method}`, { subTag: 'Ignored' });
            } else {
                traceMethod(`${targetClass}.${method}`, printStack);
            }
        });

        hook.$dispose();
    });
}

// 打印对象字段
function printObjFields(obj) {
    LOG('Printing object fields');
    try {
        const fields = obj.class.getDeclaredFields();
        fields.forEach(field => {
            field.setAccessible(true);
            const name = field.getName();
            const value = field.get(obj)?.toString() ?? 'null';
            LOG(`name: ${name}\tvalue: ${value}`);
        });
    } catch (e) {
        LOG(`Error printing fields: ${e}`, { level: 'error' });
    }
}

// 通用 Hook 函数
function hookMethod(classAndMethod, callback = null, printStack = false) {
    
    if (!classAndMethod.includes('#')) return;

    const [className, methodName] = classAndMethod.split('#');
    Java.perform(() => {
        LOG(`Hooking [${classAndMethod}]`);

        let clazz;
        try {
            clazz = Java.use(className);
        } catch (e) {
            LOG(`Failed to load class ${className}: ${e}`, { level: 'error' });
            return;
        }

        const methods = clazz.class.getDeclaredMethods();
        const methodExists = methods.some(m => m.getName() === methodName);
        LOG(`All methods: ${methods.map(m => m.getName()).join(', ')}`, { subTag: 'Methods' });

        if (!methodExists) {
            LOG(`Method ${methodName} not found in ${className}`, { level: 'error' });
            return;
        }

        const overloadCount = clazz[methodName].overloads.length;
        clazz[methodName].overloads.forEach((overload, i) => {
            overload.implementation = function (...args) {
                if (printStack) printStackTrace(`Call to ${classAndMethod}`);

                const log = {
                    hookInfo: `${classAndMethod} [overload ${i}]`,
                    args: args.length ? `[${args.map(arg => arg?.toString() ?? 'null').join(', ')}]` : '[]'
                };

                let retval;
                try {
                    if (callback) {
                        // console.log('callback');
                        // console.log('this', this);
                        // console.log('args', ...args);
                        const result = callback(this, ...args);
                        if (result && result.return_type === TYPE.INTERDICT) {
                            retval = result.return_obj;
                        } else {
                            console.log('overload.apply');
                            
                            retval = overload.apply(this, args);
                        }
                    } else {
                        retval = overload.apply(this, args);
                    }
                    log.return = retval?.toString() ?? 'null';
                } catch (e) {
                    LOG(`Error in ${classAndMethod}: ${e.stack}`, { level: 'error' });
                    retval = overload.apply(this, args); // 出错时仍调用原方法
                }

                LOG(JSON.stringify(log, null, 2));
                console.log('retval', retval);
                console.log('------------------------');
                
                 return retval;
            };
        });
    });
}

// 专用 Hook 函数
const hookM = (claAndMethod, callback, printStack = false) => hookMethod(claAndMethod, callback, printStack);
const hookM_stack = (claAndMethod, callback) => hookMethod(claAndMethod, callback, true);
const hookM_overload = (claAndMethod, callback) => hookMethod(claAndMethod, callback, false);