/* Portable OpenCL 1.2 public-only secp256k1 + Ethereum Keccak-256.
 * 8 x 32-bit limbs, Jacobian mixed addition, configurable Montgomery inversion.
 * No scalar secrets, entropy, passwords, or encrypted seed enter this kernel.
 */
#ifndef BLOCK
#define BLOCK 16
#endif
typedef struct { uint v[8]; } fe;
/* BOUNDED_FIELD_SOURCE */
typedef struct { fe x,y,z; } point;
constant uint MODULUS[8]={0xfffffc2fU,0xfffffffeU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU,0xffffffffU};
constant uint GX[8]={0x16f81798U,0x59f2815bU,0x2dce28d9U,0x029bfcdbU,0xce870b07U,0x55a06295U,0xf9dcbbacU,0x79be667eU};
constant uint GY[8]={0xfb10d4b8U,0x9c47d08fU,0xa6855419U,0xfd17b448U,0x0e1108a8U,0x5da4fbfcU,0x26a3c465U,0x483ada77U};
fe zero() { fe r; for(uint i=0;i<8;i++) r.v[i]=0; return r; }
fe one() { fe r=zero(); r.v[0]=1; return r; }
int iszero(fe a) { uint v=0; for(uint i=0;i<8;i++) v|=a.v[i]; return v==0; }
int cmp(fe a,fe b) { for(int i=7;i>=0;i--) { if(a.v[i]>b.v[i]) return 1; if(a.v[i]<b.v[i]) return -1; } return 0; }
fe modulus() { fe p; for(uint i=0;i<8;i++) p.v[i]=MODULUS[i]; return p; }
fe subtract_raw(fe a,fe b) {
    fe r; ulong borrow=0;
    for(uint i=0;i<8;i++) { ulong sub=(ulong)b.v[i]+borrow; r.v[i]=(uint)((ulong)a.v[i]-sub); borrow=((ulong)a.v[i]<sub); }
    return r;
}
fe reduce(uint t[16]) {
    /* 2^256 == 2^32 + 977 (mod p). Fold all upper limbs, including carries. */
    int high=1;
    while(high) {
        for(int i=15;i>=8;i--) {
            ulong x=t[i]; t[i]=0;
            ulong carry=x*977UL; uint j=(uint)i-8;
            while(carry) { carry+=(ulong)t[j]; t[j]=(uint)carry; carry>>=32; j++; }
            carry=x; j=(uint)i-7;
            while(carry) { carry+=(ulong)t[j]; t[j]=(uint)carry; carry>>=32; j++; }
        }
        high=0; for(uint i=8;i<16;i++) high|=t[i]!=0;
    }
    fe r; for(uint i=0;i<8;i++) r.v[i]=t[i];
    fe p=modulus(); if(cmp(r,p)>=0) r=subtract_raw(r,p); return r;
}
#ifdef CANONICAL_FIELD
/* Original Vanity Pro arithmetic experiment. MIT project license.
 * Contract: every fe is the canonical integer in [0,p), p=2^256-2^32-977.
 * No secret inputs are accepted by the OpenCL engine.
 */
fe add(fe a,fe b) {
    fe r; ulong carry=0;
    for(uint i=0;i<8;i++) {
        ulong sum=(ulong)a.v[i]+b.v[i]+carry;
        r.v[i]=(uint)sum;carry=sum>>32;
    }
    if(carry) {
        /* a+b<2p implies low(a+b)+(2^32+977)<p: no second carry. */
        ulong c=(ulong)r.v[0]+977UL;r.v[0]=(uint)c;c>>=32;
        c+=(ulong)r.v[1]+1UL;r.v[1]=(uint)c;c>>=32;
        for(uint i=2;i<8;i++){c+=(ulong)r.v[i];r.v[i]=(uint)c;c>>=32;}
        return r;
    }
    fe p=modulus();return cmp(r,p)>=0?subtract_raw(r,p):r;
}
fe sub(fe a,fe b) {
    fe r;ulong borrow=0;
    for(uint i=0;i<8;i++) {
        ulong av=(ulong)a.v[i],bv=(ulong)b.v[i]+borrow;
        r.v[i]=(uint)(av-bv);borrow=av<bv;
    }
    if(borrow) {
        /* Wrapped a-b is corrected by +p modulo2^256. Final carry discarded. */
        ulong carry=0;
        for(uint i=0;i<8;i++) {
            ulong sum=(ulong)r.v[i]+MODULUS[i]+carry;
            r.v[i]=(uint)sum;carry=sum>>32;
        }
    }
    return r;
}
#else
fe add(fe a,fe b) {
    uint t[16]={0}; ulong carry=0;
    for(uint i=0;i<8;i++) { carry+=(ulong)a.v[i]+b.v[i]; t[i]=(uint)carry; carry>>=32; }
    t[8]=(uint)carry; return reduce(t);
}
fe sub(fe a,fe b) { if(cmp(a,b)>=0) return subtract_raw(a,b); return subtract_raw(modulus(),subtract_raw(b,a)); }
#endif
fe mul(fe a,fe b) {
#ifdef BOUNDED_MULTIPLY
    return mul_bounded_schoolbook(a,b);
#elif defined(WIDE_MULTIPLY)
    /* 4x64 schoolbook product with explicit high halves, then the independent
     * canonical prime reduction. No 128-bit OpenCL extension is required. */
    ulong x[4],y[4],t[8]={0};
    for(uint i=0;i<4;i++) {x[i]=(ulong)a.v[2*i]|((ulong)a.v[2*i+1]<<32);y[i]=(ulong)b.v[2*i]|((ulong)b.v[2*i+1]<<32);}
    for(uint i=0;i<4;i++) {
        ulong carry=0;
        for(uint j=0;j<4;j++) {
            ulong lo=x[i]*y[j],hi=mul_hi(x[i],y[j]);
            ulong v=lo+t[i+j];hi+=(v<lo);
            ulong w=v+carry;hi+=(w<v);t[i+j]=w;carry=hi;
        }
        t[i+4]=carry;
    }
    uint words[16];for(uint i=0;i<8;i++) {words[2*i]=(uint)t[i];words[2*i+1]=(uint)(t[i]>>32);}
    return reduce(words);
#elif defined(FAST_FIELD)
    mp_number x,y,r;for(uint i=0;i<8;i++) {x.d[i]=a.v[i];y.d[i]=b.v[i];}
    mp_mod_mul(&r,&x,&y);fe out;for(uint i=0;i<8;i++) out.v[i]=r.d[i];return out;
#else
    uint t[16]={0};
    for(uint i=0;i<8;i++) {
        ulong carry=0;
        for(uint j=0;j<8;j++) { ulong v=(ulong)a.v[i]*b.v[j]+t[i+j]+carry; t[i+j]=(uint)v; carry=v>>32; }
        t[i+8]=(uint)carry;
    } return reduce(t);
#endif
}
fe sq(fe a) { return mul(a,a); }
fe twice(fe a) { return add(a,a); }
fe inverse(fe a) {
#ifdef FAST_FIELD
    if(iszero(a)) return zero();
    mp_number r;for(uint i=0;i<8;i++) r.d[i]=a.v[i];
    mp_mod_inverse(&r);mp_number prime=mod;if(mp_gte(&r,&prime)) mp_sub_mod(&r);
    fe out;for(uint i=0;i<8;i++) out.v[i]=r.d[i];return out;
#else
    /* Fermat exponent p-2; the input is public. Zero is handled by the caller. */
    fe r=one();
    for(int bit=255;bit>=0;bit--) {
        r=sq(r); uint word=MODULUS[bit/32]; if(bit/32==0) word-=2;
        if((word>>(bit%32))&1U) r=mul(r,a);
    } return r;
#endif
}
point infinity() { point r; r.x=zero(); r.y=one(); r.z=zero(); return r; }
point doubling(point p) {
    if(iszero(p.z)||iszero(p.y)) return infinity();
    fe a=sq(p.x),b=sq(p.y),c=sq(b);
    fe d=twice(sub(sub(sq(add(p.x,b)),a),c));
    fe e=add(twice(a),a),f=sq(e);
    point r; r.x=sub(f,twice(d));
    r.y=sub(mul(e,sub(d,r.x)),twice(twice(twice(c)))); r.z=twice(mul(p.y,p.z)); return r;
}
point advance(point p,fe gx,fe gy) {
    if(iszero(p.z)) {point r;r.x=gx;r.y=gy;r.z=one();return r;}
    fe z2=sq(p.z),u=mul(gx,z2),s=mul(gy,mul(p.z,z2));
    fe h=sub(u,p.x),delta=sub(s,p.y);
    if(iszero(h)) {if(iszero(delta)) return doubling(p); return infinity();}
    fe hh=sq(h),i=twice(twice(hh)),j=mul(h,i),rr=twice(delta),v=mul(p.x,i);
    point r; r.x=sub(sub(sq(rr),j),twice(v));
    r.y=sub(mul(rr,sub(v,r.x)),twice(mul(p.y,j)));
    r.z=sub(sub(sq(add(p.z,h)),z2),hh); return r;
}
point next(point p) {
    fe gx,gy;for(uint i=0;i<8;i++) {gx.v[i]=GX[i];gy.v[i]=GY[i];}
    return advance(p,gx,gy);
}
constant ulong RC[24]={
  0x0000000000000001UL,0x0000000000008082UL,0x800000000000808aUL,0x8000000080008000UL,
  0x000000000000808bUL,0x0000000080000001UL,0x8000000080008081UL,0x8000000000008009UL,
  0x000000000000008aUL,0x0000000000000088UL,0x0000000080008009UL,0x000000008000000aUL,
  0x000000008000808bUL,0x800000000000008bUL,0x8000000000008089UL,0x8000000000008003UL,
  0x8000000000008002UL,0x8000000000000080UL,0x000000000000800aUL,0x800000008000000aUL,
  0x8000000080008081UL,0x8000000000008080UL,0x0000000080000001UL,0x8000000080008008UL};
constant uint ROT[25]={0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
ulong rol(ulong v,uint n) {return n==0?v:((v<<n)|(v>>(64-n)));}
/* Independent fixed-width coordinate packing. Numeric byte swaps preserve
 * the Ethereum big-endian x||y input on either OpenCL device endianness. */
#ifdef ADDRESS_KECCAK
uint eth_bswap32(uint v){return (v>>24)|((v>>8)&0xff00U)|((v<<8)&0xff0000U)|(v<<24);}
#endif
#if defined(WORD_MATCH) && defined(ADDRESS_KECCAK)
/* Original Vanity Pro public Ethereum matching, MIT.
 * Numeric little-endian words are independent of device byte order.
 * This helper reads only Keccak output lanes 1..3, bytes 12..31. */
typedef struct { uint w0,w1,w2,w3,w4; } eth_payload_words;
uint eth_pattern_u32(global const uchar* p) {
    return (uint)p[0]|((uint)p[1]<<8)|((uint)p[2]<<16)|((uint)p[3]<<24);
}
#define ETH_WORD_TEST(N) ((((w.w##N)^eth_pattern_u32(pattern+84+4*N))&eth_pattern_u32(pattern+64+4*N))==0U)
int eth_words_matching(eth_payload_words w,global const uchar* pattern,uint prefix,uint suffix) {
    /* Start at the constrained edge for the usual fast rejection. These fixed
     * fields avoid private arrays with dynamically indexed byte/nibble access. */
    if(prefix) return ETH_WORD_TEST(0)&&ETH_WORD_TEST(1)&&ETH_WORD_TEST(2)&&ETH_WORD_TEST(3)&&ETH_WORD_TEST(4);
    return ETH_WORD_TEST(4)&&ETH_WORD_TEST(3)&&ETH_WORD_TEST(2)&&ETH_WORD_TEST(1)&&ETH_WORD_TEST(0);
}
#undef ETH_WORD_TEST
void eth_words_bytes(eth_payload_words w,uchar out[20]) {
    /* Executed only when diagnostics or an accepted hit needs all bytes. */
    for(uint i=0;i<4;i++) {
        out[i]=(uchar)(w.w0>>(8*i));out[4+i]=(uchar)(w.w1>>(8*i));
        out[8+i]=(uchar)(w.w2>>(8*i));out[12+i]=(uchar)(w.w3>>(8*i));
        out[16+i]=(uchar)(w.w4>>(8*i));
    }
}
eth_payload_words eth_address_words(fe x,fe y) {
    ethhash h={{0}};
    h.q[0]=(ulong)eth_bswap32(x.v[7])|((ulong)eth_bswap32(x.v[6])<<32);
    h.q[1]=(ulong)eth_bswap32(x.v[5])|((ulong)eth_bswap32(x.v[4])<<32);
    h.q[2]=(ulong)eth_bswap32(x.v[3])|((ulong)eth_bswap32(x.v[2])<<32);
    h.q[3]=(ulong)eth_bswap32(x.v[1])|((ulong)eth_bswap32(x.v[0])<<32);
    h.q[4]=(ulong)eth_bswap32(y.v[7])|((ulong)eth_bswap32(y.v[6])<<32);
    h.q[5]=(ulong)eth_bswap32(y.v[5])|((ulong)eth_bswap32(y.v[4])<<32);
    h.q[6]=(ulong)eth_bswap32(y.v[3])|((ulong)eth_bswap32(y.v[2])<<32);
    h.q[7]=(ulong)eth_bswap32(y.v[1])|((ulong)eth_bswap32(y.v[0])<<32);
    h.q[8]^=1UL;
#ifdef TERNARY_KECCAK
    sha3_keccakf_ternary_address(&h);
#else
    sha3_keccakf_address(&h);
#endif
    eth_payload_words w;
    w.w0=(uint)(h.q[1]>>32);w.w1=(uint)h.q[2];w.w2=(uint)(h.q[2]>>32);
    w.w3=(uint)h.q[3];w.w4=(uint)(h.q[3]>>32);
    return w;
}
#endif
void eth_address(fe x,fe y,uchar out[20]) {
#ifdef TUNED_KECCAK
    ethhash h={{0}};
#ifdef ADDRESS_KECCAK
    h.q[0]=(ulong)eth_bswap32(x.v[7])|((ulong)eth_bswap32(x.v[6])<<32);
    h.q[1]=(ulong)eth_bswap32(x.v[5])|((ulong)eth_bswap32(x.v[4])<<32);
    h.q[2]=(ulong)eth_bswap32(x.v[3])|((ulong)eth_bswap32(x.v[2])<<32);
    h.q[3]=(ulong)eth_bswap32(x.v[1])|((ulong)eth_bswap32(x.v[0])<<32);
    h.q[4]=(ulong)eth_bswap32(y.v[7])|((ulong)eth_bswap32(y.v[6])<<32);
    h.q[5]=(ulong)eth_bswap32(y.v[5])|((ulong)eth_bswap32(y.v[4])<<32);
    h.q[6]=(ulong)eth_bswap32(y.v[3])|((ulong)eth_bswap32(y.v[2])<<32);
    h.q[7]=(ulong)eth_bswap32(y.v[1])|((ulong)eth_bswap32(y.v[0])<<32);
#else
    for(uint i=0;i<64;i++) {
        fe f=i<32?x:y;uint pos=i%32;
        uchar byte=(uchar)(f.v[7-pos/4]>>(8*(3-pos%4)));
        h.q[i/8]|=(ulong)byte<<(8*(i%8));
    }
#endif
    h.q[8]^=1UL; /* Full Ethereum Keccak, not FIPS SHA3. */
#ifdef ADDRESS_KECCAK
    /* Only output lanes 1..3 are valid; this caller reads bytes 12..31 only. */
#ifdef TERNARY_KECCAK
    sha3_keccakf_ternary_address(&h);
#else
    sha3_keccakf_address(&h);
#endif
#else
    sha3_keccakf(&h);
#endif
    for(uint i=0;i<20;i++) {uint p=i+12;out[i]=(uchar)(h.q[p/8]>>(8*(p%8)));}
#else
    ulong a[25]={0},b[25],c[5],d[5];
    for(uint i=0;i<64;i++) {
        fe f=i<32?x:y; uint pos=i%32;
        uchar byte=(uchar)(f.v[7-pos/4]>>(8*(3-pos%4)));
        a[i/8]|=(ulong)byte<<(8*(i%8));
    }
    a[8]^=1UL; a[16]^=0x8000000000000000UL; /* Ethereum domain, not SHA3. */
    for(uint round=0;round<24;round++) {
        for(uint i=0;i<5;i++) c[i]=a[i]^a[i+5]^a[i+10]^a[i+15]^a[i+20];
        for(uint i=0;i<5;i++) d[i]=c[(i+4)%5]^rol(c[(i+1)%5],1);
        for(uint j=0;j<5;j++) for(uint i=0;i<5;i++) {uint k=i+5*j;b[j+5*((2*i+3*j)%5)]=rol(a[k]^d[i],ROT[k]);}
        for(uint j=0;j<5;j++) for(uint i=0;i<5;i++) a[i+5*j]=b[i+5*j]^((~b[(i+1)%5+5*j])&b[(i+2)%5+5*j]);
        a[0]^=RC[round];
    }
    for(uint i=0;i<20;i++) {uint pos=i+12;out[i]=(uchar)(a[pos/8]>>(8*(pos%8)));}
#endif
}
int matching(uchar addr[20],global const uchar* pattern,uint prefix,uint suffix) {
    for(uint i=0;i<prefix;i++) {uchar n=(i%2==0)?(addr[i/2]>>4):(addr[i/2]&15);if(n!=pattern[i]) return 0;}
    for(uint i=0;i<suffix;i++) {uint j=40-suffix+i;uchar n=(j%2==0)?(addr[j/2]>>4):(addr[j/2]&15);if(n!=pattern[prefix+i]) return 0;}
    return 1;
}
fe load_fe(global const uchar* bytes) {
    fe r=zero();for(uint i=0;i<32;i++) r.v[7-i/4]|=(uint)bytes[i]<<(8*(3-i%4));return r;
}
void store_fe(fe a,global uchar* bytes) {for(uint i=0;i<32;i++) bytes[i]=(uchar)(a.v[7-i/4]>>(8*(3-i%4)));}
/* Public candidate-family metadata; matching bytes retain their original layout. */
#ifdef LINEAR_SEARCH
/* Compile out orbit state only for jobs whose persisted strategy is linear. */
uint orbit_width(global const uchar* p){return 1;}
uint orbit_count(global const uchar* p,uint base_count){return base_count;}
int orbit_allowed(global const uchar* p,uint base,uint branch,uint base_count){return base<base_count;}
#else
uint orbit_width(global const uchar* p){uint w=p[484];return w==3||w==6?w:1;}
uint orbit_count(global const uchar* p,uint base_count){uint n=(uint)p[488]|((uint)p[489]<<8)|((uint)p[490]<<16)|((uint)p[491]<<24);return n?n:base_count;}
int orbit_allowed(global const uchar* p,uint base,uint branch,uint base_count){uint index=base*orbit_width(p)+branch,skip=p[485];return index>=skip&&index-skip<orbit_count(p,base_count);}
#endif
fe orbit_x(fe x,uint power){if(!power)return x;fe beta;
if(power==1){beta.v[0]=0x719501eeU;beta.v[1]=0xc1396c28U;beta.v[2]=0x12f58995U;beta.v[3]=0x9cf04975U;beta.v[4]=0xac3434e9U;beta.v[5]=0x6e64479eU;beta.v[6]=0x657c0710U;beta.v[7]=0x7ae96a2bU;}
else{beta.v[0]=0x8e6afa40U;beta.v[1]=0x3ec693d6U;beta.v[2]=0xed0a766aU;beta.v[3]=0x630fb68aU;beta.v[4]=0x53cbcb16U;beta.v[5]=0x919bb861U;beta.v[6]=0x9a83f8efU;beta.v[7]=0x851695d4U;}
return mul(x,beta);}
/* Each lane has a reference-CPU public starting point and advances BLOCK offsets.
 * One output slot per lane, so matches cannot overflow a shared append buffer.
 * diagnostics=1 returns every point/address for independent startup validation.
 */
kernel void search(global const uchar* starts,global const uchar* valid,
                   global const uchar* pattern,uint prefix,uint suffix,uint count,
                   uint batched,uint diagnostics,global uint* hits,
                   global uchar* addresses,global uchar* points,
                   global point* states,uint reuse,uint persist,
                   global const uchar* jump,uint jump_valid,global uint* invalid) {
    uint lane=(uint)get_global_id(0),base=lane*BLOCK;
    if(base>=count) return;
    point current;
    if(reuse) current=states[lane];
    else {current.x=load_fe(starts+lane*64);current.y=load_fe(starts+lane*64+32);current.z=valid[lane]?one():zero();}
    point batch[BLOCK];fe products[BLOCK];fe accum=one();uint size=min((uint)BLOCK,count-base);
    for(uint i=0;i<size;i++) {
        batch[i]=current;products[i]=accum;
        if(!iszero(current.z)) accum=mul(accum,current.z);
        current=next(current);
    }
    /* Each lane owns BLOCK consecutive offsets. Advance its public state to the
     * same lane in the next contiguous interval, not merely the next BLOCK points.
     * The coordinator remains authoritative; discontinuities never reuse state.
     */
    if(persist) {
        if(jump_valid) current=advance(current,load_fe(jump),load_fe(jump+32));
        states[lane]=current;
    }
    fe inv=batched?inverse(accum):one();hits[lane]=0xffffffffU;
    if(!diagnostics) for(uint j=0;j<20;j++) addresses[lane*20+j]=0;
    for(int i=(int)size-1;i>=0;i--) {
        point p=batch[i];fe zi=one();
        if(!iszero(p.z)) {
            if(batched) {zi=mul(inv,products[i]);inv=mul(inv,p.z);} else {zi=inverse(p.z);}
            fe z2=sq(zi),base_x=mul(p.x,z2),base_y=mul(p.y,mul(z2,zi));
            uint base_index=base+(uint)i;
            if(!diagnostics && (base_index==0 || base_index==count-1)){uint slot=base_index==0?0:1;store_fe(base_x,points+slot*65+1);store_fe(base_y,points+slot*65+33);points[slot*65]=4;}
            uint family=orbit_width(pattern);
            for(uint power=0;power<(family==1?1:3);power++){
             fe tx=orbit_x(base_x,power);
             for(uint sign=0;sign<(family==6?2:1);sign++){
              uint branch=power+3*sign;if(!orbit_allowed(pattern,base_index,branch,count))continue;
              fe x=tx,y=sign?sub(zero(),base_y):base_y;uchar addr[20];eth_address(x,y,addr);
              uint index=base_index*family+branch;
              if(diagnostics){for(uint j=0;j<20;j++)addresses[index*20+j]=addr[j];store_fe(x,points+index*65+1);store_fe(y,points+index*65+33);points[index*65]=4;}
              if(matching(addr,pattern,prefix,suffix) && index<hits[lane]){hits[lane]=index;if(!diagnostics)for(uint j=0;j<20;j++)addresses[lane*20+j]=addr[j];}
             }
            }
        } else {uint missing=0;for(uint branch=0;branch<orbit_width(pattern);branch++)if(orbit_allowed(pattern,base+(uint)i,branch,count))missing++;atomic_add(invalid,missing);
        if(diagnostics) {for(uint j=0;j<65;j++) points[(base+(uint)i)*65+j]=0;}
        else if(base+(uint)i==0 || base+(uint)i==count-1) {
            uint slot=base+(uint)i==0?0:1;
            for(uint j=0;j<65;j++) points[slot*65+j]=0;
        }
        }
    }
}
