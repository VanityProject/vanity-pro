/* Diagnostic stage probes only. Their global outputs keep all arithmetic live.
 * Extra VRAM traffic means isolated times cannot be summed as fused-kernel cost.
 * These kernels never run as production search and never report completed work.
 */
kernel void profile_seed(global const uchar* starts,global const uchar* valid,
                         uint count,global point* projected) {
    uint lane=(uint)get_global_id(0),base=lane*BLOCK;
    if(base>=count) return;
    point p;p.x=load_fe(starts+lane*64);p.y=load_fe(starts+lane*64+32);
    p.z=valid[lane]?one():zero();projected[base]=p;
}
kernel void profile_curve(global const uchar* starts,global const uchar* valid,
                          uint count,global point* projected) {
    uint lane=(uint)get_global_id(0),base=lane*BLOCK;
    if(base>=count) return;
    point p;p.x=load_fe(starts+lane*64);p.y=load_fe(starts+lane*64+32);
    p.z=valid[lane]?one():zero();
    for(uint i=0;i<min((uint)BLOCK,count-base);i++) {projected[base+i]=p;p=next(p);}
}
kernel void profile_inverse(global const point* projected,uint count,global fe* inverses) {
    uint lane=(uint)get_global_id(0),base=lane*BLOCK;
    if(base>=count) return;
    uint size=min((uint)BLOCK,count-base);fe products[BLOCK],accum=one();
    for(uint i=0;i<size;i++) {
        products[i]=accum;fe z=projected[base+i].z;
        if(!iszero(z)) accum=mul(accum,z);
    }
    fe inv=inverse(accum);
    for(int i=(int)size-1;i>=0;i--) {
        fe z=projected[base+(uint)i].z,zi=zero();
        if(!iszero(z)) {zi=mul(inv,products[i]);inv=mul(inv,z);}
        inverses[base+(uint)i]=zi;
    }
}
kernel void profile_affine(global const point* projected,global const fe* inverses,
                           uint count,global uchar* affine) {
    uint i=(uint)get_global_id(0);if(i>=count) return;
    point p=projected[i];fe zi=inverses[i];
    if(iszero(p.z)) {for(uint j=0;j<65;j++) affine[i*65+j]=0;return;}
    fe z2=sq(zi),x=mul(p.x,z2),y=mul(p.y,mul(z2,zi));
    affine[i*65]=4;store_fe(x,affine+i*65+1);store_fe(y,affine+i*65+33);
}
kernel void profile_keccak(global const uchar* affine,uint count,global uchar* hashes) {
    uint i=(uint)get_global_id(0);if(i>=count) return;
    uchar addr[20];
    eth_address(load_fe(affine+i*65+1),load_fe(affine+i*65+33),addr);
    for(uint j=0;j<20;j++) hashes[i*20+j]=addr[j];
}
kernel void profile_match(global const uchar* hashes,global const uchar* pattern,
                          uint prefix,uint suffix,uint count,global uint* matches) {
    uint i=(uint)get_global_id(0);if(i>=count) return;
    uchar addr[20];for(uint j=0;j<20;j++) addr[j]=hashes[i*20+j];
    matches[i]=(uint)matching(addr,pattern,prefix,suffix);
}
