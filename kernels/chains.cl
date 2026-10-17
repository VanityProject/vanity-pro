/* Public-only chain hashes and encoded suffix matching, OpenCL C 1.2.
 * SHA-256 (FIPS 180-4), RIPEMD-160 (ISO/IEC 10118-3), BIP173/350/341.
 * RIPEMD round schedules generated from RustCrypto/ripemd 0.1.3 (MIT/Apache-2.0).
 */
constant uint CH_SHA_K[64]={0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
uint ch_rotr(uint x,uint n){return rotate(x,32U-n);}
void ch_sha(uchar* input,uint len,uchar* out){
    uint h[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    uint blocks=(len+9+63)/64;
    for(uint block=0;block<blocks;block++){
        uint w[64];for(uint i=0;i<16;i++){w[i]=0;for(uint j=0;j<4;j++){uint p=block*64+i*4+j;uchar b=p<len?input[p]:(p==len?128:0);if(p>=blocks*64-4)b=(uchar)((len*8)>>(8*(blocks*64-1-p)));w[i]=(w[i]<<8)|b;}}
        for(uint i=16;i<64;i++){uint x=w[i-15],y=w[i-2];w[i]=w[i-16]+(ch_rotr(x,7)^ch_rotr(x,18)^(x>>3))+w[i-7]+(ch_rotr(y,17)^ch_rotr(y,19)^(y>>10));}
        uint a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(uint i=0;i<64;i++){uint t=hh+(ch_rotr(e,6)^ch_rotr(e,11)^ch_rotr(e,25))+((e&f)^((~e)&g))+CH_SHA_K[i]+w[i];uint t2=(ch_rotr(a,2)^ch_rotr(a,13)^ch_rotr(a,22))+((a&b)^(a&c)^(b&c));hh=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+t2;}
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }for(uint i=0;i<32;i++)out[i]=(uchar)(h[i/4]>>(8*(3-i%4)));
}
constant uchar CH_RL[80]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
constant uchar CH_SL[80]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
constant uchar CH_RR[80]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
constant uchar CH_SR[80]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
constant uint CH_KL[5]={0,0x5a827999U,0x6ed9eba1U,0x8f1bbcdcU,0xa953fd4eU};
constant uint CH_KR[5]={0x50a28be6U,0x5c4dd124U,0x6d703ef3U,0x7a6d76e9U,0};
uint ch_rf(uint r,uint x,uint y,uint z){if(r==0)return x^y^z;if(r==1)return(x&y)|((~x)&z);if(r==2)return(x|(~y))^z;if(r==3)return(x&z)|(y&(~z));return x^(y|(~z));}
void ch_ripemd(uchar* input,uchar* out){
    uint x[16]={0};for(uint i=0;i<32;i++)x[i/4]|=(uint)input[i]<<(8*(i%4));x[8]=128;x[14]=256;
    uint h[5]={0x67452301U,0xefcdab89U,0x98badcfeU,0x10325476U,0xc3d2e1f0U};
    uint a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],aa=a,bb=b,cc=c,dd=d,ee=e;
    for(uint i=0;i<80;i++){uint r=i/16;uint t=rotate(a+ch_rf(r,b,c,d)+x[CH_RL[i]]+CH_KL[r],(uint)CH_SL[i])+e;a=e;e=d;d=rotate(c,10U);c=b;b=t;t=rotate(aa+ch_rf(4-r,bb,cc,dd)+x[CH_RR[i]]+CH_KR[r],(uint)CH_SR[i])+ee;aa=ee;ee=dd;dd=rotate(cc,10U);cc=bb;bb=t;}
    uint t=h[1]+c+dd;h[1]=h[2]+d+ee;h[2]=h[3]+e+aa;h[3]=h[4]+a+bb;h[4]=h[0]+b+cc;h[0]=t;for(uint i=0;i<20;i++)out[i]=(uchar)(h[i/4]>>(8*(i%4)));
}
void ch_fe_bytes(fe a,uchar* out){for(uint i=0;i<32;i++)out[i]=(uchar)(a.v[7-i/4]>>(8*(3-i%4)));}
/* TAPROOT_POWERS */
void chain_address(fe x,fe y,uchar* out){
    for(uint i=0;i<33;i++)out[i]=0;out[32]=1;
#if CH_HASH == 0
    legacy_eth_address(x,y,out);
#elif CH_HASH == 1
    uchar input[33],sha[32];input[0]=2+(y.v[0]&1);ch_fe_bytes(x,input+1);ch_sha(input,33,sha);ch_ripemd(sha,out);
#else
    uchar input[96],tag[32],tweak[32];uchar name[8]={'T','a','p','T','w','e','a','k'};ch_sha(name,8,tag);for(uint i=0;i<32;i++){input[i]=tag[i];input[i+32]=tag[i];}ch_fe_bytes(x,input+64);ch_sha(input,96,tweak);
    uint order[8]={0xd0364141U,0xbfd25e8cU,0xaf48a03bU,0xbaaedce6U,0xfffffffeU,0xffffffffU,0xffffffffU,0xffffffffU};int comparison=0;
    for(uint i=0;i<8;i++){uint t=0;for(uint j=0;j<4;j++)t=(t<<8)|tweak[i*4+j];uint n=order[7-i];if(!comparison&&t!=n)comparison=t>n?1:-1;}
    if(comparison>=0){out[32]=0;for(uint i=0;i<32;i++)out[i]=0;return;}
    point q;q.x=x;q.y=(y.v[0]&1)?sub(zero(),y):y;q.z=one();
    for(uint bit=0;bit<256;bit++)if((tweak[31-bit/8]>>(bit%8))&1){fe gx,gy;for(uint i=0;i<8;i++){gx.v[i]=CH_GX[bit*8+i];gy.v[i]=CH_GY[bit*8+i];}q=advance(q,gx,gy);}
    if(iszero(q.z)){out[32]=0;for(uint i=0;i<32;i++)out[i]=0;return;}
    fe zi=inverse(q.z);ch_fe_bytes(mul(q.x,sq(zi)),out);
#endif
}
constant char CH_B58[] = CH_ALPHABET;
constant char CH_B32[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
uint ch_encode(uchar* payload,uchar* text){
#if CH_ENCODING == 3
    uchar checksum[32];ch_sha(payload,20,checksum);
    for(uint i=0;i<24;i++){uchar b=i<20?payload[i]:checksum[i-20];text[2*i]=CH_B58[b>>4];text[2*i+1]=CH_B58[b&15];}return 48;
#elif CH_ENCODING == 0
    uchar input[25],a[32],b[32];input[0]=CH_VERSION;for(uint i=0;i<20;i++)input[i+1]=payload[i];ch_sha(input,21,a);ch_sha(a,32,b);for(uint i=0;i<4;i++)input[i+21]=b[i];
    uint z=0;while(z<25&&input[z]==0)z++;uchar digits[36];uint length=0;
    for(uint i=z;i<25;i++){uint carry=input[i];for(uint j=0;j<length;j++){carry+=(uint)digits[j]*256;digits[j]=(uchar)(carry%58);carry/=58;}while(carry){digits[length++]=(uchar)(carry%58);carry/=58;}}
    for(uint i=0;i<z;i++)text[i]=CH_B58[0];for(uint i=0;i<length;i++)text[z+i]=CH_B58[digits[length-1-i]];return z+length;
#else
    constant char* hrp=CH_HRP;uint hlen=CH_HRP_LEN;uint start=0;
    for(uint i=0;i<hlen;i++)text[start++]=hrp[i];text[start++]=CH_SEPARATOR;
    uchar data[64];uint size=0;
#if CH_ENCODING == 1
#if CH_WITNESS >= 0
    data[size++]=CH_WITNESS;
#endif
    uint acc=0,bits=0;for(uint i=0;i<CH_LENGTH;i++){acc=(acc<<8)|payload[i];bits+=8;while(bits>=5){bits-=5;data[size++]=(uchar)((acc>>bits)&31);}}if(bits)data[size++]=(uchar)((acc<<(5-bits))&31);
    uint c=1;
    for(uint pass=0;pass<2;pass++)for(uint i=0;i<hlen;i++){uint v=pass?(hrp[i]&31):(hrp[i]>>5);uint top=c>>25;c=((c&0x1ffffff)<<5)^v;uint gen[5]={0x3b6a57b2U,0x26508e6dU,0x1ea119faU,0x3d4233ddU,0x2a1462b3U};for(uint j=0;j<5;j++)if((top>>j)&1)c^=gen[j];if(pass==0&&i==hlen-1){top=c>>25;c=(c&0x1ffffff)<<5;for(uint j=0;j<5;j++)if((top>>j)&1)c^=gen[j];}}
    uint gen[5]={0x3b6a57b2U,0x26508e6dU,0x1ea119faU,0x3d4233ddU,0x2a1462b3U};
    for(uint i=0;i<size+6;i++){uint v=i<size?data[i]:0;uint top=c>>25;c=((c&0x1ffffff)<<5)^v;for(uint j=0;j<5;j++)if((top>>j)&1)c^=gen[j];}
    c^=CH_CHECKSUM;for(uint i=0;i<size;i++)text[start++]=CH_B32[data[i]];for(int i=5;i>=0;i--)text[start++]=CH_B32[(c>>(5*i))&31];return start;
#else
    uint acc=0,bits=0;for(uint i=0;i<21;i++){acc=(acc<<8)|(i?payload[i-1]:0);bits+=8;while(bits>=5){bits-=5;data[size++]=(uchar)((acc>>bits)&31);}}if(bits)data[size++]=(uchar)((acc<<(5-bits))&31);
    ulong c=1;ulong gen[5]={0x98f2bc8e61UL,0x79b76d99e2UL,0xf33e5fb3c4UL,0xae2eabe2a8UL,0x1e4f43e470UL};
    for(uint i=0;i<hlen+1+size+8;i++){uint v=i<hlen?(hrp[i]&31):(i==hlen?0:(i<hlen+1+size?data[i-hlen-1]:0));ulong top=c>>35;c=((c&0x07ffffffffUL)<<5)^v;for(uint j=0;j<5;j++)if((top>>j)&1)c^=gen[j];}c^=1;
    for(uint i=0;i<size;i++)text[start++]=CH_B32[data[i]];for(int i=7;i>=0;i--)text[start++]=CH_B32[(c>>(5*i))&31];return start;
#endif
#endif
}
int chain_matching(uchar* addr,global const uchar* wire,uint prefix,uint suffix){
    if(!addr[32])return 0;
    for(uint i=0;i<CH_LENGTH;i++)if((addr[i]&wire[4+i])!=wire[36+i])return 0;
    uint range_count=wire[1];if(range_count){uint found=0;for(uint k=0;k<range_count;k++){int lo=0,hi=0;for(uint i=0;i<20;i++){uchar a=wire[68+k*40+i],b=wire[88+k*40+i];if(!lo&&addr[i]!=a)lo=addr[i]>a?1:-1;if(!hi&&addr[i]!=b)hi=addr[i]>b?1:-1;}found|=(lo>=0&&hi<=0);}if(!found)return 0;}
    uint slen=wire[2];if(!slen)return 1;
#if CH_ENCODING == 3
    uchar checksum[32];
#ifdef CH_FIXED_HASH
    ch_sha20_fixed(addr,checksum);
#else
    ch_sha(addr,20,checksum);
#endif
    uint length=min(slen,8U);for(uint i=0;i<length;i++){uint p=8-length+i;uchar nibble=(p&1)?(checksum[p/2]&15):(checksum[p/2]>>4);if(CH_B58[nibble]!=wire[388+slen-length+i])return 0;}return 1;
#else
    uchar text[96];uint n=ch_encode(addr,text);if(slen>n)return 0;for(uint i=0;i<slen;i++)if(text[n-slen+i]!=wire[388+i])return 0;return 1;
#endif
}
kernel void chain_probe(global const uchar* points,global uchar* payloads,uint count){uint id=get_global_id(0);if(id>=count)return;uchar out[33];chain_address(load_fe(points+id*64),load_fe(points+id*64+32),out);for(uint i=0;i<33;i++)payloads[id*33+i]=out[i];}
