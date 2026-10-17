/* Mandatory public finite-field known-answer checks; never private key data. */
kernel void field_probe(global const uint* inputs,uint count,global uint* outputs) {
    uint id=(uint)get_global_id(0);if(id>=count) return;
    fe a,b;for(uint i=0;i<8;i++) {a.v[i]=inputs[id*16+i];b.v[i]=inputs[id*16+8+i];}
    fe results[4];results[0]=add(a,b);results[1]=sub(a,b);
    results[2]=mul(a,b);results[3]=inverse(a);
    for(uint op=0;op<4;op++) for(uint i=0;i<8;i++) outputs[id*32+op*8+i]=results[op].v[i];
}

