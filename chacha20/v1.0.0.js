class algoEncrypt{
                #useAlgo="chacha20"
                #algo={}
                #support_algo=["chacha20"]
                #chacha20_constant={constant:new Uint32Array([1634760805,857760878,2036477234,1797285236])}
                constructor(algorithm="chacha20"){
                    const algo_lower=algorithm.toLowerCase()
                    if (!this.#support_algo.includes(algo_lower)){
                        throw new Error(`The algorithm "${algo_lower}" is not supported. The only supported algorithm is " ${this.#support_algo.join(" , ")} ".`)
                    }
                    this.#useAlgo=algo_lower
                    this.#algo={chacha20:{e:this.chacha20_e.bind(this),d:this.chacha20_d.bind(this)}}
                }
                 /**@param {Uint32Array<8>} secrets @param {Uint32Array<1>} counter @param {Uint32Array<3>} nonce */
                chacha20_algo(secrets,counter,nonce){
                    function cs(v,s){
                        return (v<<s)|(v>>>(32-s))
                    }
                    function qr(a,b,c,d){
                        a=(a+b)&0xFFFFFFFF
                        d=cs((d^a),16)

                        c=(c+d)&0xFFFFFFFF
                        b=cs((b^c),12)

                        a=(a+b)&0xFFFFFFFF
                        d=cs((d^a),8)

                        c=(c+d)&0xFFFFFFFF
                        b=cs((b^c),7)
                        return [a,b,c,d]
                    }
                    function data_qr(A,B,C,D){
                        const _A=data[Math.floor(A/4)]
                        const _B=data[Math.floor(B/4)]
                        const _C=data[Math.floor(C/4)]
                        const _D=data[Math.floor(D/4)]
                        const ai=A%4
                        const bi=B%4
                        const ci=C%4
                        const di=D%4
                        const [a,b,c,d]=qr(_A[ai],_B[bi],_C[ci],_D[di])
                        _A[ai]=a
                        _B[bi]=b
                        _C[ci]=c
                        _D[di]=d
                    }
                    const constant=this.#chacha20_constant.constant
                    const data_index3=new Uint32Array(4)
                    data_index3.set(counter,0)
                    data_index3.set(nonce,1)
                    const data=[
                        structuredClone(constant),
                        new Uint32Array(secrets.subarray(0,4)),
                        new Uint32Array(secrets.subarray(4,8)),
                        data_index3
                    ]
                    const datacopy=structuredClone(data)
                    for (let i=0;i<10;i++){
                        data_qr(0,4,8,12)
                        data_qr(1,5,9,13)
                        data_qr(2,6,10,14)
                        data_qr(3,7,11,15)
                        data_qr(0,5,10,15)
                        data_qr(1,6,11,12)
                        data_qr(2,7,8,13)
                        data_qr(3,4,9,14)
                    }
                    for (let i=0;i<4;i++){
                        for (let i2=0;i2<4;i2++){
                            data[i][i2]=(data[i][i2]+datacopy[i][i2])&0xFFFFFFFF
                        }
                    }
                    const result=new Uint32Array(16)
                    for (let i=0;i<4;i++){
                        result.set(data[i],i*4)
                    }
                    return result
                }
                /**@param {Uint8Array} data @param {Uint32Array|undefined} key */
                chacha20_e(data,key=undefined,base64=!!Uint8Array.prototype.toBase64){
                    let k=new Uint32Array(8)
                    let d=structuredClone(data)
                    const nonce=crypto.getRandomValues(new Uint32Array(3))
                    if (key===undefined){
                        k.set(crypto.getRandomValues(new Uint32Array(8)),0)
                    }else{
                        k.set(key,0)
                    }
                    for (let i=0;i<Math.ceil(d.length/64);i++){
                        const e=d.subarray(64*i,64*i+64)
                        const algo_out = this.chacha20_algo(k, new Uint32Array([i]), nonce);
                        const chacha20_result = new Uint8Array(algo_out.buffer, algo_out.byteOffset, algo_out.byteLength);
                        for (let j=0;j<e.length;j++){
                            e[j]=e[j]^chacha20_result[j]
                        }
                    }
                    if (base64){
                        //return [d.toBase64(),new Uint8Array(nonce.buffer).toBase64(),new Uint8Array(k.buffer).toBase64()]
                        return {encryptedData:d,encryptedDataBase64:d.toBase64(),nonce:nonce,nonceBase64:new Uint8Array(nonce.buffer).toBase64(),key:k,keyBase64:new Uint8Array(k.buffer).toBase64()}
                    }else{
                        return [d,nonce,k]
                    }
                }
                /**@param {Uint8Array} data @param {Uint32Array} key @param {Uint32Array} nonce*/
                chacha20_d(data,key,nonce_,base64=!!Uint8Array.prototype.toBase64){
                    let k=new Uint32Array(8)
                    k.set(key,0)
                    let nonce=new Uint32Array(3)
                    nonce.set(nonce_,0)
                    let d=structuredClone(data)
                    for (let i=0;i<Math.ceil(d.length/64);i++){
                        const e=d.subarray(64*i,64*i+64)
                        const algo_out = this.chacha20_algo(k, new Uint32Array([i]), nonce);
                        const chacha20_result = new Uint8Array(algo_out.buffer, algo_out.byteOffset, algo_out.byteLength);
                        for (let j=0;j<e.length;j++){
                            e[j]=e[j]^chacha20_result[j]
                        }
                    }
                    if (base64){
                        return d.toBase64()
                    }else{
                        return d
                    }
                }
                encrypt(data,key=undefined,base64=!!Uint8Array.prototype.toBase64){
                    let pack=null
                    let k=null
                    if (typeof data==="string"||typeof data==="number"||typeof data==="bigint"){
                        pack=new TextEncoder().encode(data)
                    }else if (data instanceof Uint8Array){
                        pack=data
                    }else if (data instanceof Uint16Array){
                        pack=new Uint8Array(data.buffer)
                    }else if (data instanceof Uint32Array){
                        pack=new Uint8Array(data.buffer)
                    }
                    try{
                        k=Uint8Array.fromBase64(key)
                    }catch(e){
                        k=new Uint8Array(key.buffer, key.byteOffset, key.byteLength)
                    }
                    if (pack===null){
                        return undefined
                    }else{
                        k=structuredClone(new Uint32Array(k.buffer,k.byteOffset,k.byteLength/4))
                    }
                    return this.#algo[this.#useAlgo].e(pack,k,base64)
                }
                decrypt(data,key,nonce,base64=!!Uint8Array.prototype.toBase64){
                    let pack=null
                    let k=null
                    let ne=null
                    try{
                        pack=Uint8Array.fromBase64(data)
                    }catch(e){
                        pack=new Uint8Array(data.buffer)
                    }
                    try{
                        k=Uint8Array.fromBase64(key)
                    }catch(e){
                        k=new Uint8Array(key.buffer, key.byteOffset, key.byteLength)
                    }
                    try{
                        ne=Uint8Array.fromBase64(nonce)
                    }catch(e){
                        ne=new Uint8Array(nonce.buffer, nonce.byteOffset, nonce.byteLength)
                    }
                    if (pack===null||k===null||ne===null){
                        return undefined
                    }else{
                        k=structuredClone(new Uint32Array(k.buffer,k.byteOffset,k.byteLength/4))
                        ne=structuredClone(new Uint32Array(ne.buffer,ne.byteOffset,ne.byteLength/4))
                    }
                    return this.#algo[this.#useAlgo].d(pack,k,ne,base64)
                }
            }
