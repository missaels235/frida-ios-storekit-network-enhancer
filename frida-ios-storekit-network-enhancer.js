/*
 * Script Altamente Mejorado para Hooking de StoreKit y Red en iOS con Frida
 * Nota: La simulación de validación de compra requiere que el usuario defina la estructura de una respuesta exitosa
 * para la API específica de la aplicación en CONFIG.FAKE_SUCCESS_VALIDATION_RESPONSE.
 */

// Bandera para prevenir re-inicialización
if (global.fridaHookScriptLoaded_v6_1_4_enhanced) {
    console.log("[INFO] Script v6.1.4 (enhanced) ya cargado. Omitiendo re-inicialización.");
} else {
    global.fridaHookScriptLoaded_v6_1_4_enhanced = true;

    (function() {
        "use strict";

        // --- Configuración Global ---
        const CONFIG = {
            ENABLE_POLLING_TRANSACTIONS: false,
            POLLING_INTERVAL_MS: 3000,
            MAX_BODY_LOG_LENGTH: 2048,
            LOG_VERBOSE_NETWORK: true,
            LOG_VERBOSE_STOREKIT: true,
            VALIDATION_URL_SUBSTRING: "/validate",
            FAKE_SUCCESS_VALIDATION_RESPONSE: {
                "status": "success",
                "isValid": true,
                "message": "Transaction validated successfully (simulated by Frida).",
                "subscription_active": true,
                "product_id": "app.generic.item", // Actualizar con el product_id correcto si es posible
                "purchase_date_ms": Date.now() - (1000 * 60 * 5),
                "expires_date_ms": Date.now() + (1000 * 60 * 60 * 24 * 30)
            }
        };

        // --- Constantes ---
        const LOG_PREFIX = {
            INFO: "[INFO]", STOREKIT: "[STOREKIT]", NETWORK: "[NETWORK]",
            NETWORK_REQ: "[NET_REQ]", NETWORK_RESP: "[NET_RESP]", VALIDATE_HOOK: "[VALIDATE_HOOK]",
            ERROR: "[ERROR]", WARN: "[WARN]", DEBUG: "[DEBUG]"
        };

        const SKPaymentTransactionState = {
            Purchasing: 0, Purchased: 1, Failed: 2, Restored: 3, Deferred: 4
        };

        const SKNotification = {
            TransactionUpdated: 'SKPaymentQueueTransactionUpdatedNotification',
            QueueChanged: 'SKPaymentQueueDidChangeNotification'
        };

        // --- Funciones Helper ---
        function arrayBufferToHexString(buffer) {
            if (!buffer || buffer.byteLength === 0) return "";
            return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
        }

        function safeToString(nsStringObj, defaultVal = "N/A (nil)") {
            if (!nsStringObj || nsStringObj.isNull()) { return defaultVal; }
            try { return nsStringObj.toString(); }
            catch (e) { return `Error convirtiendo a string: ${e.message}`; }
        }

        function logData(prefix, dataObj, maxLength) {
            if (!dataObj || dataObj.isNull()) { console.log(`${prefix} (nil)`); return ""; } // Devolver string vacío para cuerpo
            let bodyToLog = "";
            if (!ObjC.classes.NSData || !dataObj.isKindOfClass_(ObjC.classes.NSData)) {
                const className = (dataObj && dataObj.$className) ? dataObj.$className : typeof dataObj;
                console.log(`${prefix} (No es NSData: ${className})`);
                if (typeof dataObj === 'string') {
                    bodyToLog = dataObj;
                    if (bodyToLog.length > maxLength) bodyToLog = bodyToLog.substring(0, maxLength) + `... (Total ${dataObj.length} chars)`;
                    console.log(`${prefix} ${bodyToLog}`);
                } else if (typeof dataObj === 'object') { // Podría ser un JSON ya parseado o un objeto para stringify
                    try {
                        bodyToLog = JSON.stringify(dataObj);
                        if (bodyToLog.length > maxLength) bodyToLog = bodyToLog.substring(0, maxLength) + `... (Total ${bodyToLog.length} chars stringified)`;
                        console.log(`${prefix} ${bodyToLog}`);
                    } catch (e) {
                        console.log(`${prefix} (Objeto no serializable a JSON: ${e.message})`);
                        bodyToLog = `(Objeto no serializable: ${e.message})`;
                    }
                } else {
                     bodyToLog = `(Tipo de dato inesperado: ${className})`;
                     console.log(`${prefix} ${bodyToLog}`);
                }
                return bodyToLog.substring(0, maxLength); // Devolver el cuerpo procesado (o parte de él)
            }

            // Es NSData
            const bodyLength = dataObj.length();
            if (bodyLength.toNumber() === 0) { console.log(`${prefix} (Cuerpo Vacío - 0 bytes)`); return ""; }
            
            const bodyPointer = dataObj.bytes();
            if (!bodyPointer || bodyPointer.isNull()) { console.log(`${prefix} (Puntero de bytes es nil)`); return ""; }
            
            const currentLengthToRead = bodyLength.toNumber(); // Leer todo para el return, truncar solo para log
            let fullBodyStringUtf8 = null;

            try {
                fullBodyStringUtf8 = bodyPointer.readUtf8String(currentLengthToRead);
            } catch (e) { /* Ignorar error aquí, se manejará abajo */ }

            if (fullBodyStringUtf8 !== null && !fullBodyStringUtf8.includes('\uFFFD')) {
                bodyToLog = fullBodyStringUtf8;
            } else { // No es UTF-8 válido o falló la lectura
                const maxHexBytesToLog = Math.min(currentLengthToRead, maxLength / 2); // Cada byte son 2 chars hex
                try {
                    const byteArray = bodyPointer.readByteArray(maxHexBytesToLog);
                    bodyToLog = "(Hex) " + arrayBufferToHexString(byteArray);
                    if (currentLengthToRead > maxHexBytesToLog) bodyToLog += "...";
                } catch (e) {
                    bodyToLog = `(Error leyendo bytes para Hex: ${e.message})`;
                }
                // Para el return, si no es UTF8, no devolvemos nada como "string parseable"
                fullBodyStringUtf8 = ""; // Indicar que no se pudo obtener como UTF-8 completo
            }
            
            // Logueo truncado
            let logDisplayString = bodyToLog;
            if (bodyToLog.length > maxLength) {
                 logDisplayString = bodyToLog.substring(0, maxLength) + `... (Total ${bodyLength.toNumber()} bytes, ${bodyToLog.length} chars procesados)`;
            }
            console.log(`${prefix} ${logDisplayString}`);
            
            return fullBodyStringUtf8; // Devolver el string UTF-8 completo si se pudo, o vacío
        }


        // --- Funciones de Hook Seguras ---
        function safeReplaceMethod(cls, methodSelector, replacementCallback, retType, argTypes) {
            if (!cls) { console.warn(`${LOG_PREFIX.WARN} Clase ${cls} no definida para ${methodSelector}`); return null; }
            const method = cls[methodSelector];
            if (method && method.implementation) {
                let originalImpl = method.implementation;
                try { method.implementation = new NativeCallback(replacementCallback, retType, argTypes); console.log(`${LOG_PREFIX.INFO} [🛠️] Hook REEMPLAZADO: ${cls.$className}.${methodSelector}`); return originalImpl; }
                catch (e) { console.error(`${LOG_PREFIX.ERROR} Fallo al reemplazar ${cls.$className}.${methodSelector}: ${e.message}`); method.implementation = originalImpl; return null; }
            } else { console.warn(`${LOG_PREFIX.WARN} [🚫] Método no encontrado: ${cls.$className}.${methodSelector}`); return null; }
        }
        function safeAttachHook(cls, methodSelector, callbacks) {
            if (!cls) { console.warn(`${LOG_PREFIX.WARN} Clase ${cls} no definida para ${methodSelector}`); return; }
            const method = cls[methodSelector];
            if (method && method.implementation) {
                try { Interceptor.attach(method.implementation, callbacks); console.log(`${LOG_PREFIX.INFO} [👂] Hook ATTACHED: ${cls.$className}.${methodSelector}`); }
                catch (e) { console.error(`${LOG_PREFIX.ERROR} Fallo al attachear ${cls.$className}.${methodSelector}: ${e.message}`); }
            } else { console.warn(`${LOG_PREFIX.WARN} [🚫] Método no encontrado: ${cls.$className}.${methodSelector}`); }
        }

        // --- Verificación Principal ---
        if (!ObjC.available) { console.error(`${LOG_PREFIX.ERROR} Objective-C Runtime no disponible.`); return; }
        console.log(`${LOG_PREFIX.INFO} Objective-C Runtime detectado.`);

        // --- Definiciones de Clases Objective-C ---
        const SKPaymentQueue = ObjC.classes.SKPaymentQueue;
        const SKPaymentTransaction = ObjC.classes.SKPaymentTransaction;
        const NSURLSession = ObjC.classes.NSURLSession;
        const NSNotificationCenter = ObjC.classes.NSNotificationCenter;
        const NSString = ObjC.classes.NSString;
        const NSMutableURLRequest = ObjC.classes.NSMutableURLRequest;
        const NSData = ObjC.classes.NSData;
        const NSHTTPURLResponse = ObjC.classes.NSHTTPURLResponse;
        const NSArray = ObjC.classes.NSArray;
        const NSDictionary = ObjC.classes.NSDictionary;
        const NSError = ObjC.classes.NSError;

        // --- Hooks de StoreKit ---
        if (SKPaymentQueue) {
            console.log(`${LOG_PREFIX.STOREKIT} 🚀 StoreKit Detectado. Iniciando hooks...`);
            if (SKPaymentTransaction) {
                safeReplaceMethod(SKPaymentTransaction, '- transactionState', function() {
                    console.log(`${LOG_PREFIX.STOREKIT} [➡️] Hook -[SKPaymentTransaction transactionState]. Forzando 'Purchased' (${SKPaymentTransactionState.Purchased}).`);
                    return SKPaymentTransactionState.Purchased;
                }, 'long', ['pointer']);
                safeReplaceMethod(SKPaymentTransaction, '- error', function() {
                    console.log(`${LOG_PREFIX.STOREKIT} [➡️] Hook -[SKPaymentTransaction error]. Forzando nil.`);
                    return NULL;
                }, 'pointer', ['pointer']);
            }
            safeAttachHook(SKPaymentQueue, '- addPayment:', {
                onEnter: function(args) {
                    try { 
                        const paymentObj = new ObjC.Object(args[2]); // SKPayment *
                        const productIdentifier = safeToString(paymentObj.productIdentifier());
                        this.currentProductId = productIdentifier; // Guardar para posible uso en FAKE_SUCCESS_VALIDATION_RESPONSE
                        console.log(`${LOG_PREFIX.STOREKIT} [🛒] Intento de compra para: ${productIdentifier}`);
                    } catch (e) { console.error(`${LOG_PREFIX.ERROR} Error en onEnter de addPayment: ${e.message}\n${e.stack}`); }
                }
            });
            
            // Configuración del observador de notificaciones de StoreKit
            console.log(`${LOG_PREFIX.STOREKIT} Configurando observador de notificaciones...`);
            const defaultCenter = NSNotificationCenter.defaultCenter();

            if (!defaultCenter || defaultCenter.isNull()) {
                console.error(`${LOG_PREFIX.ERROR} NSNotificationCenter.defaultCenter() es nulo o inválido. Saltando observador.`);
            } else {
                if (!global.fridaIosHookNotificationCallback) { // Evitar redefinir
                    global.fridaIosHookNotificationCallback = new ObjC.Block({
                        retType: 'void',
                        argTypes: ['object'], // id notification
                        implementation: function(notificationPtr) {
                            try {
                                if (!notificationPtr || notificationPtr.isNull()) {
                                    console.warn(`${LOG_PREFIX.WARN} [Notificación SK] Puntero de notificación es nil.`);
                                    return;
                                }
                                const notificationObj = new ObjC.Object(notificationPtr);
                                const name = safeToString(notificationObj.name());
                                
                                if (CONFIG.LOG_VERBOSE_STOREKIT) {
                                    console.log(`${LOG_PREFIX.STOREKIT} [🔔 SK] Notificación Recibida: ${name}`);
                                }

                                if (name === SKNotification.TransactionUpdated) {
                                    const userInfo = notificationObj.userInfo();
                                    if (userInfo && !userInfo.isNull() && userInfo.isKindOfClass_(NSDictionary)) {
                                        const transactionsKey = NSString.stringWithString_('SKPaymentQueueTransactions');
                                        const transactionsArray = userInfo.objectForKey_(transactionsKey);

                                        if (transactionsArray && !transactionsArray.isNull() && transactionsArray.isKindOfClass_(NSArray)) {
                                            const numTransactions = transactionsArray.count().toNumber();
                                            if (numTransactions > 0) {
                                                console.log(`${LOG_PREFIX.STOREKIT}   -> Procesando ${numTransactions} transacción(es) de ${name}...`);
                                                for (let i = 0; i < numTransactions; i++) {
                                                    const transaction = new ObjC.Object(transactionsArray.objectAtIndex_(i));
                                                    const transactionId = safeToString(transaction.transactionIdentifier(), "N/A");
                                                    const state = transaction.transactionState();
                                                    let stateString = Object.keys(SKPaymentTransactionState).find(key => SKPaymentTransactionState[key] === state) || 'Unknown';
                                                    console.log(`${LOG_PREFIX.STOREKIT}     -> Tx Notificada: ID=${transactionId}, Estado=${stateString} (${state})`);
                                                }
                                            } else { console.log(`${LOG_PREFIX.STOREKIT}   -> Notificación ${name} sin transacciones en userInfo.`); }
                                        } else { console.log(`${LOG_PREFIX.STOREKIT}   -> userInfo no contiene un NSArray de transacciones para ${name}.`); }
                                    } else { console.log(`${LOG_PREFIX.STOREKIT}   -> Notificación ${name} sin userInfo válido o no es NSDictionary.`); }
                                } else if (name === SKNotification.QueueChanged) {
                                    console.log(`${LOG_PREFIX.STOREKIT}   -> La cola de pagos cambió (Notificación: ${name}).`);
                                }
                            } catch (e) {
                                console.error(`${LOG_PREFIX.ERROR} [Notificación SK] Error procesando notificación: ${e.message}\n${e.stack}`);
                            }
                        }
                    }); // Fin de new ObjC.Block
                } // Fin de if (!global.fridaIosHookNotificationCallback)

                const notificationNameUpdatedStr = NSString.stringWithString_(SKNotification.TransactionUpdated);
                const notificationNameChangedStr = NSString.stringWithString_(SKNotification.QueueChanged);
                const invokeSelector = ObjC.selector('invoke:');

                if (notificationNameUpdatedStr && !notificationNameUpdatedStr.isNull()) {
                    try { defaultCenter.addObserver_selector_name_object_(global.fridaIosHookNotificationCallback, invokeSelector, notificationNameUpdatedStr, null); console.log(`${LOG_PREFIX.STOREKIT} [👂 SK] Observando: ${SKNotification.TransactionUpdated}`); }
                    catch(e) { console.error(`${LOG_PREFIX.ERROR} Fallo al observar ${SKNotification.TransactionUpdated}: ${e.message}`); }
                }
                if (notificationNameChangedStr && !notificationNameChangedStr.isNull()) {
                    try { defaultCenter.addObserver_selector_name_object_(global.fridaIosHookNotificationCallback, invokeSelector, notificationNameChangedStr, null); console.log(`${LOG_PREFIX.STOREKIT} [👂 SK] Observando: ${SKNotification.QueueChanged}`); }
                    catch(e) { console.error(`${LOG_PREFIX.ERROR} Fallo al observar ${SKNotification.QueueChanged}: ${e.message}`); }
                }
            }
            console.log(`${LOG_PREFIX.INFO} ✅ Hooks de StoreKit configurados.`);
        } else { console.warn(`${LOG_PREFIX.WARN} ❌ StoreKit (SKPaymentQueue) no disponible.`); }


        // --- Hooks de Red ---
        console.log(`${LOG_PREFIX.NETWORK} Configurando hooks de red...`);
        if (NSURLSession && NSURLSession['- dataTaskWithRequest:completionHandler:']) {
            safeAttachHook(NSURLSession, '- dataTaskWithRequest:completionHandler:', {
                onEnter: function(args) {
                    try {
                        const request = new ObjC.Object(args[2]); // NSURLRequest *
                        const urlObj = request.URL();
                        const url = urlObj ? safeToString(urlObj.absoluteString()) : "URL N/A";
                        this.requestURL = url; // Guardar para el completionHandler
                        this.currentProductId = "unknown_product"; // Reset/default
                        if (typeof this.currentProductIdFromStoreKit !== 'undefined') { // Propagado desde addPayment:
                            this.currentProductId = this.currentProductIdFromStoreKit;
                        }

                        const method = safeToString(request.HTTPMethod(), "[No HTTP Method]");
                        this.requestId = `${method} ${url.substring(0, 70)}..._${Date.now()}`;
                        console.log(`${LOG_PREFIX.NETWORK_REQ} [🌐 NSURLSession] ID: ${this.requestId} URL: ${url}`);

                        if (CONFIG.LOG_VERBOSE_NETWORK) {
                            const headers = request.allHTTPHeaderFields();
                            if (headers && !headers.isNull() && headers.isKindOfClass_(NSDictionary)) {
                                const keys = headers.allKeys();
                                const count = keys.count().toNumber();
                                console.log(`${LOG_PREFIX.NETWORK_REQ}   -> Headers Petición (${count}):`);
                                for (let i = 0; i < count; i++) {
                                    const keyObj = keys.objectAtIndex_(i);
                                    const valueObj = headers.objectForKey_(keyObj);
                                    console.log(`${LOG_PREFIX.NETWORK_REQ}     - ${safeToString(keyObj)}: ${safeToString(valueObj)}`);
                                }
                            } else { console.log(`${LOG_PREFIX.NETWORK_REQ}   -> Headers Petición: (nil o no es NSDictionary)`); }
                        }
                        const httpBody = request.HTTPBody(); // NSData*
                        logData(`${LOG_PREFIX.NETWORK_REQ}   -> Cuerpo Petición:`, httpBody, CONFIG.MAX_BODY_LOG_LENGTH);
                    } catch (e) { console.error(`${LOG_PREFIX.ERROR} Error en onEnter de dataTask: ${e.message}\n${e.stack}`); }
                },
                implementation: function(originalCompletionHandlerPtr, dataPtr, responsePtr, errorPtr) {
                    console.log(`${LOG_PREFIX.NETWORK_RESP} [↩️ NSURLSession] ID: ${this.requestId}`);
                    
                    let originalRequestURL = this.requestURL || "";
                    let currentResponseObj = null;
                    let currentErrorObj = null;
                    // currentDataObj se manejará dentro de la lógica de modificación/logueo

                    let finalResponsePtr = responsePtr;
                    let finalDataPtr = dataPtr;
                    let finalErrorPtr = errorPtr;

                    let responseModified = false;
                    let httpStatusCode = -1; // Default si no se puede leer

                    if (errorPtr && !errorPtr.isNull()) {
                        try { currentErrorObj = new ObjC.Object(errorPtr); console.log(`${LOG_PREFIX.NETWORK_RESP}   -> Error Original: ${safeToString(currentErrorObj.localizedDescription())}`); }
                        catch (e_err) { console.error(`${LOG_PREFIX.ERROR} Error procesando errorPtr: ${e_err.message}`); }
                    }

                    if (responsePtr && !responsePtr.isNull()) {
                        try {
                            currentResponseObj = new ObjC.Object(responsePtr);
                            if (currentResponseObj.isKindOfClass_(NSHTTPURLResponse)) {
                                const httpResponse = currentResponseObj.as(NSHTTPURLResponse);
                                try { httpStatusCode = httpResponse.statusCode().valueOf(); console.log(`${LOG_PREFIX.NETWORK_RESP}   -> Estado Original: ${httpStatusCode}`); } // valueOf para asegurar número JS
                                catch (e_status) { console.error(`${LOG_PREFIX.ERROR} Error obteniendo statusCode: ${e_status.message}. Invalidando responsePtr.`); finalResponsePtr = NULL; }

                                if (finalResponsePtr !== NULL) { // Solo si no se invalidó
                                    try { console.log(`${LOG_PREFIX.NETWORK_RESP}   -> URL Respuesta: ${safeToString(httpResponse.URL().absoluteString())}`); } catch(_){}
                                    if (CONFIG.LOG_VERBOSE_NETWORK) {
                                        try {
                                            const headers = httpResponse.allHeaderFields();
                                            if (headers && !headers.isNull() && headers.isKindOfClass_(NSDictionary)) {
                                                console.log(`${LOG_PREFIX.NETWORK_RESP}     -> Headers Originales: ${safeToString(headers.description())}`);
                                            } else { console.warn(`${LOG_PREFIX.WARN} allHeaderFields no devolvió NSDictionary.`);}
                                        } catch (e_hdrs) { console.error(`${LOG_PREFIX.ERROR} Error logueando headers: ${e_hdrs.message}`); }
                                    }
                                }
                            } else {
                                console.warn(`${LOG_PREFIX.WARN} responsePtr no es NSHTTPURLResponse. Clase: ${currentResponseObj.$className}`);
                                finalResponsePtr = NULL; 
                            }
                        } catch (e_resp_main) {
                            console.error(`${LOG_PREFIX.ERROR} Error GRAVE procesando responsePtr: ${e_resp_main.message}\n${e_resp_main.stack}`);
                            finalResponsePtr = NULL;
                        }
                    }

                    let originalBodyStr = "";
                    if (finalResponsePtr !== NULL && dataPtr && !dataPtr.isNull()) { // Solo procesar data si la respuesta parece válida
                        const tempNsData = new ObjC.Object(dataPtr);
                        originalBodyStr = logData(`${LOG_PREFIX.NETWORK_RESP}   -> Cuerpo Original:`, tempNsData, CONFIG.MAX_BODY_LOG_LENGTH);
                    } else if (finalResponsePtr === NULL && dataPtr && !dataPtr.isNull()) {
                        console.log(`${LOG_PREFIX.NETWORK_RESP}   -> Cuerpo Original (responsePtr fue anulado, se omite parseo pero se lista si existe):`);
                        logData(`${LOG_PREFIX.NETWORK_RESP}      `, new ObjC.Object(dataPtr), CONFIG.MAX_BODY_LOG_LENGTH);
                    }


                    if (originalRequestURL.includes(CONFIG.VALIDATION_URL_SUBSTRING)) {
                        console.log(`${LOG_PREFIX.VALIDATE_HOOK} Petición de validación detectada para: ${originalRequestURL}`);
                        let validationFailedServerSide = false;
                        if (currentErrorObj) validationFailedServerSide = true;
                        if (httpStatusCode !== 200 && httpStatusCode !== -1) validationFailedServerSide = true;
                        
                        try {
                            if (originalBodyStr && originalBodyStr.trim().startsWith("{")) { // Intentar parsear solo si parece JSON
                                const jsonData = JSON.parse(originalBodyStr);
                                if (jsonData.error || jsonData.isValid === false || jsonData.status === "error" || (jsonData.data && jsonData.data.error)) {
                                    validationFailedServerSide = true;
                                }
                                // Actualizar product_id en la respuesta falsa si es posible
                                if (jsonData.product_id) CONFIG.FAKE_SUCCESS_VALIDATION_RESPONSE.product_id = jsonData.product_id;
                                else if (jsonData.data && jsonData.data.product_id) CONFIG.FAKE_SUCCESS_VALIDATION_RESPONSE.product_id = jsonData.data.product_id;
                                else if (this.currentProductId) CONFIG.FAKE_SUCCESS_VALIDATION_RESPONSE.product_id = this.currentProductId;

                            } else if (originalBodyStr) { // No es JSON, pero hay cuerpo. Podría ser un error HTML, etc.
                                if(httpStatusCode !== 200) validationFailedServerSide = true; // Si no es 200 y hay cuerpo, probablemente error
                            }
                        } catch (e_parse) { console.log(`${LOG_PREFIX.VALIDATE_HOOK} Cuerpo original no es JSON o error al parsear: ${e_parse.message}`); }
                        
                        if (validationFailedServerSide) {
                            console.warn(`${LOG_PREFIX.VALIDATE_HOOK} Validación original PARECE FALLIDA. Intentando simular éxito.`);
                            
                            const fakeSuccessBodyJson = { ...CONFIG.FAKE_SUCCESS_VALIDATION_RESPONSE }; // Copiar para modificar product_id
                             if (this.currentProductId && this.currentProductId !== "unknown_product") { // Usar el product ID de la compra actual
                                fakeSuccessBodyJson.product_id = this.currentProductId;
                            }

                            const fakeSuccessBodyStr = JSON.stringify(fakeSuccessBodyJson);
                            const newNsData = NSString.stringWithString_(fakeSuccessBodyStr).dataUsingEncoding_(4); // NSUTF8StringEncoding

                            finalDataPtr = newNsData.handle;
                            responseModified = true;
                            logData(`${LOG_PREFIX.VALIDATE_HOOK} Cuerpo de respuesta MODIFICADO a:`, new ObjC.Object(finalDataPtr), CONFIG.MAX_BODY_LOG_LENGTH);

                            if(currentErrorObj) { console.log(`${LOG_PREFIX.VALIDATE_HOOK} Anulando error de red original.`); finalErrorPtr = NULL; }
                            
                            // Si el statusCode original era de error y finalResponsePtr no es NULL, la app podría aun ver ese statusCode.
                            // Esto es una limitación. Idealmente crearíamos un nuevo NSHTTPURLResponse con status 200.
                            if (finalResponsePtr !== NULL && httpStatusCode !== 200) {
                                 console.warn(`${LOG_PREFIX.VALIDATE_HOOK} ADVERTENCIA: statusCode original era ${httpStatusCode}. La app podría rechazar el cuerpo modificado si espera un NSHTTPURLResponse con status 200.`);
                            } else if (finalResponsePtr == NULL && httpStatusCode !== 200) { // Si el response original ya era problemático
                                console.warn(`${LOG_PREFIX.VALIDATE_HOOK} Response original era problemático. La simulación de datos podría no ser suficiente.`);
                                // Aquí podríamos considerar crear un mock de NSHTTPURLResponse con status 200 si es crucial, pero es complejo.
                            }

                        } else {
                            console.log(`${LOG_PREFIX.VALIDATE_HOOK} Validación original parece exitosa o no se detectó fallo. No se modifica.`);
                        }
                    }
                    
                    const originalHandler = new ObjC.Block(originalCompletionHandlerPtr);
                    if (originalHandler.implementation) {
                        try {
                            if (CONFIG.LOG_VERBOSE_NETWORK || responseModified) {
                                console.log(`${LOG_PREFIX.DEBUG} Invocando handler original. Modificado: ${responseModified}. Args: data=${finalDataPtr}, response=${finalResponsePtr}, error=${finalErrorPtr}`);
                            }
                            originalHandler.implementation(finalDataPtr, finalResponsePtr, finalErrorPtr);
                        } catch (invocationError) {
                            console.error(`${LOG_PREFIX.ERROR} Error invocando IMPL del handler original: ${invocationError.message}\n${invocationError.stack}`);
                        }
                    } else { console.warn(`${LOG_PREFIX.WARN} Handler original no tiene implementación callable.`); }
                }
            });
        } else { console.log(`${LOG_PREFIX.NETWORK} NSURLSession dataTaskWithRequest:completionHandler: no encontrado.`); }

        if (NSMutableURLRequest && NSMutableURLRequest['- setHTTPBody:']) {
            safeAttachHook(NSMutableURLRequest, '- setHTTPBody:', {
                 onEnter: function(args) {
                    try {
                        const bodyDataPtr = args[2];
                        if (!bodyDataPtr || bodyDataPtr.isNull()) { console.log(`${LOG_PREFIX.NETWORK_REQ} [📦 setHTTPBody] Cuerpo es nil.`); return; }
                        logData(`${LOG_PREFIX.NETWORK_REQ} [📦 setHTTPBody]:`, new ObjC.Object(bodyDataPtr), CONFIG.MAX_BODY_LOG_LENGTH);
                    } catch (e) { console.error(`${LOG_PREFIX.ERROR} Error en setHTTPBody:onEnter: ${e.message}`); }
                }
            });
        } else { console.log(`${LOG_PREFIX.NETWORK} NSMutableURLRequest setHTTPBody: no encontrado.`); }

        console.log(`${LOG_PREFIX.INFO} ✅ Hooks de Red configurados.`);
        console.log(`${LOG_PREFIX.INFO} Script de hooking v6.1.4 iniciado. Esperando actividad...`);

    })();
}
