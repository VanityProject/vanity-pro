/* Contiguous public-offset GPU walks. No entropy or private scalar is accepted.
 * Affine and slope-recurrence variants share complete exceptional-point handling.
 * Per-lane first-match slots + atomic minimum implement a bounded single-wallet
 * result contract without an append queue or an overflowing match allocation.
 */
typedef struct {fe hx,hy,x2,y2,double_slope,neg_y,neg_2y,triple_x;} r_step;
fe r_constant_fe(constant const uchar* bytes) {
    fe r=zero();for(uint i=0;i<32;i++) r.v[7-i/4]|=(uint)bytes[i]<<(8*(3-i%4));return r;
}
kernel void r_prepare_step(global const uchar* input,global r_step* output) {
    r_step s;s.hx=load_fe(input);s.hy=load_fe(input+32);
    s.x2=load_fe(input+64);s.y2=load_fe(input+96);
    fe xx=sq(s.hx);s.double_slope=mul(add(twice(xx),xx),inverse(twice(s.hy)));
    s.neg_y=sub(zero(),s.hy);s.neg_2y=sub(zero(),twice(s.hy));
    s.triple_x=add(twice(s.hx),s.hx);output[0]=s;
}
kernel void r_initialize(global const uchar* base,constant const uchar* powers,
                         uint lanes,global fe* xs,global fe* ys,global fe* zs,
                         global uint* flags) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    point p;p.x=load_fe(base+1);p.y=load_fe(base+33);p.z=base[0]?one():zero();
    for(uint bit=0;bit<22;bit++) if(id&(1U<<bit))
        p=advance(p,r_constant_fe(powers+bit*64),r_constant_fe(powers+bit*64+32));
    xs[id]=p.x;ys[id]=p.y;zs[id]=p.z;flags[id]=iszero(p.z)?0:1;
}
/* Move cached public points by a public offset difference. This does not
 * enumerate, skip or count work; the coordinator still assigns exact ranges. */
kernel void r_jump(global const uchar* delta,uint lanes,global fe* xs,
                   global fe* ys,global fe* zs,global uint* flags,
                   constant const r_step* step,uint recurrence) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    uint f=flags[id];point p=infinity();
    if(f>(recurrence?3U:1U)) {flags[id]=4;xs[id]=zero();ys[id]=zero();zs[id]=one();return;}
    if(recurrence) {
        if(f==1) {p.x=add(xs[id],step->hx);p.y=sub(step->neg_y,mul(ys[id],xs[id]));p.z=one();}
        else if(f==2 || f==3) {p.x=step->hx;p.y=f==2?step->hy:step->neg_y;p.z=one();}
    } else if(f) {p.x=xs[id];p.y=ys[id];p.z=one();}
    if(delta[0]) p=advance(p,load_fe(delta+1),load_fe(delta+33));
    xs[id]=p.x;ys[id]=p.y;zs[id]=p.z;flags[id]=iszero(p.z)?0:1;
}
kernel void r_inverse(global const fe* source,uint lanes,global fe* inverted,
                      global fe* scratch,constant const r_step* step,uint weighted) {
    uint group=(uint)get_global_id(0),groups=(lanes+BLOCK-1)/BLOCK;
    if(group>=groups) return;
#ifdef REC_INTERLEAVED_INVERSE
    uint base=group,stride=groups,size=(lanes-1-base)/stride+1;
#else
    uint base=group*BLOCK,stride=1,size=min((uint)BLOCK,lanes-base);
#endif
    fe acc=one();
#ifndef REC_GLOBAL_PREFIX
    fe products[BLOCK];
#endif
    for(uint i=0;i<size;i++) {
        uint index=base+i*stride;
#ifdef REC_GLOBAL_PREFIX
        scratch[index]=acc;
#else
        products[i]=acc;
#endif
        fe v=source[index];if(!iszero(v)) acc=mul(acc,v);
    }
    fe inv=inverse(acc);if(weighted) inv=mul(inv,step->neg_2y);
    for(int i=(int)size-1;i>=0;i--) {
        uint index=base+(uint)i*stride;fe v=source[index],out=zero();
        if(!iszero(v)) {
#ifdef REC_GLOBAL_PREFIX
            out=mul(inv,scratch[index]);
#else
            out=mul(inv,products[i]);
#endif
            inv=mul(inv,v);
        }
        inverted[index]=out;
    }
}
kernel void r_affine(global fe* xs,global fe* ys,global const fe* zs,
                     global const fe* inverted,global uint* flags,
                     constant const r_step* step,uint lanes,uint recurrence) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    if(flags[id]>3) return;
    if(!flags[id]) {xs[id]=zero();ys[id]=zero();return;}
    fe inv=inverted[id],z2=sq(inv),x=mul(xs[id],z2),y=mul(ys[id],mul(z2,inv));
    if(recurrence) {
        x=sub(x,step->hx);
        if(iszero(x)) flags[id]=cmp(y,step->hy)==0?2:3;
    }
    xs[id]=x;ys[id]=y;
}
kernel void r_seed_slope(global const fe* delta,global fe* previous,
                         global const fe* inverted,global const uint* flags,
                         constant const r_step* step,uint lanes) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    previous[id]=flags[id]==1?mul(sub(zero(),add(previous[id],step->hy)),inverted[id]):zero();
}
kernel void r_denominators(global const fe* xs,global const uint* flags,
                           constant const r_step* step,uint lanes,global fe* denominators) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    denominators[id]=flags[id]?sub(xs[id],step->hx):zero();
}
kernel void r_reset(global uint* lane_hits,uint lanes,global uint* minimum,
                    global uint* invalid,global uint* fault,global uchar* endpoints) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    lane_hits[id]=0xffffffffU;
    if(id==0) {minimum[0]=0xffffffffU;invalid[0]=0;fault[0]=0;for(uint i=0;i<130;i++) endpoints[i]=0;}
}
void r_emit(fe x,fe y,uint finite,uint index,uint count,uint lane,
            global const uchar* pattern,uint prefix,uint suffix,
            global uint* lane_hits,global uchar* lane_addresses,global uint* minimum,
            global uint* invalid,global uchar* endpoints,uint diagnostic,
            global uchar* diagnostic_addresses,global uchar* diagnostic_points) {
    if(index>=count) return;
    if(!finite) {
        uint missing=0;for(uint branch=0;branch<orbit_width(pattern);branch++)if(orbit_allowed(pattern,index,branch,count))missing++;atomic_add(invalid,missing);
        if(diagnostic){for(uint j=0;j<65;j++)diagnostic_points[index*65+j]=0;for(uint j=0;j<20;j++)diagnostic_addresses[index*20+j]=0;}return;
    }
    if(index==0 || index==count-1){uint slot=index==0?0:1;endpoints[slot*65]=4;store_fe(x,endpoints+slot*65+1);store_fe(y,endpoints+slot*65+33);}
    fe base_x=x,base_y=y;uint family=orbit_width(pattern);
    for(uint power=0;power<(family==1?1:3);power++){
      fe tx=orbit_x(base_x,power);
      for(uint sign=0;sign<(family==6?2:1);sign++){
        uint branch=power+3*sign;if(!orbit_allowed(pattern,index,branch,count))continue;
        uint selected=index*family+branch;
#if defined(WORD_MATCH) && defined(ADDRESS_KECCAK) && !defined(CH_HASH)
        fe x=tx,y=sign?sub(zero(),base_y):base_y;
        eth_payload_words words=eth_address_words(x,y);
        int accepted=eth_words_matching(words,pattern,prefix,suffix);
        if(diagnostic || (accepted && selected<lane_hits[lane])) {
            uchar addr[20];eth_words_bytes(words,addr);
            if(diagnostic){diagnostic_points[index*65]=4;store_fe(x,diagnostic_points+index*65+1);store_fe(y,diagnostic_points+index*65+33);for(uint j=0;j<20;j++)diagnostic_addresses[index*20+j]=addr[j];}
            if(accepted && selected<lane_hits[lane]){lane_hits[lane]=selected;for(uint j=0;j<20;j++)lane_addresses[lane*20+j]=addr[j];atomic_min(minimum,selected);}
        }
#else
        fe x=tx,y=sign?sub(zero(),base_y):base_y;uchar addr[20];eth_address(x,y,addr);
        if(diagnostic){diagnostic_points[index*65]=4;store_fe(x,diagnostic_points+index*65+1);store_fe(y,diagnostic_points+index*65+33);for(uint j=0;j<20;j++)diagnostic_addresses[index*20+j]=addr[j];}
        if(matching(addr,pattern,prefix,suffix) && selected<lane_hits[lane]){lane_hits[lane]=selected;for(uint j=0;j<20;j++)lane_addresses[lane*20+j]=addr[j];atomic_min(minimum,selected);}
#endif
      }
    }
}
#define R_ITER_ARGS global fe* xs,global fe* ys,global uint* flags,global const fe* inv, \
 constant const r_step* step,uint lanes,uint row,uint count,global const uchar* pattern, \
 uint prefix,uint suffix,global uint* lane_hits,global uchar* lane_addresses,global uint* minimum, \
 global uint* invalid,global uint* fault,global uchar* endpoints,uint diagnostic, \
 global uchar* diagnostic_addresses,global uchar* diagnostic_points
#define R_EMIT(X,Y,F) r_emit(X,Y,F,index,count,id,pattern,prefix,suffix,lane_hits,lane_addresses,minimum,invalid,endpoints,diagnostic,diagnostic_addresses,diagnostic_points)
kernel void r_iterate(R_ITER_ARGS) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    uint index=row*lanes+id,f=flags[id],next_flag=1;fe d=xs[id],l=ys[id],x,y;
    if(f==1) {
        l=sub(inv[id],l);d=sub(sub(sq(l),d),step->triple_x);
        y=sub(step->neg_y,mul(l,d));x=add(d,step->hx);
        if(iszero(d)) next_flag=cmp(y,step->hy)==0?2:3;
    } else if(f==0) {
        x=step->hx;y=step->hy;d=zero();l=zero();next_flag=2;
    } else if(f==2) {
        x=step->x2;y=step->y2;d=sub(x,step->hx);l=step->double_slope;
    } else if(f==3) {
        x=zero();y=zero();d=zero();l=zero();next_flag=0;
    } else {atomic_or(fault,1U);x=zero();y=zero();d=zero();l=zero();next_flag=0;}
    xs[id]=d;ys[id]=l;flags[id]=next_flag;
    R_EMIT(x,y,next_flag!=0);
}
kernel void a_iterate(R_ITER_ARGS) {
    uint id=(uint)get_global_id(0);if(id>=lanes) return;
    uint index=row*lanes+id,f=flags[id];fe x=xs[id],y=ys[id],nx,ny;
    if(f>1) atomic_or(fault,2U);
    R_EMIT(x,y,f!=0);
    uint next_flag=1;
    if(!f) {nx=step->hx;ny=step->hy;}
    else if(cmp(x,step->hx)==0) {
        if(cmp(y,step->hy)==0) {nx=step->x2;ny=step->y2;}
        else {nx=zero();ny=zero();next_flag=0;}
    } else {
        fe l=mul(sub(y,step->hy),inv[id]);
        nx=sub(sub(sq(l),x),step->hx);ny=sub(step->neg_y,mul(l,sub(nx,step->hx)));
    }
    xs[id]=nx;ys[id]=ny;flags[id]=next_flag;
}
void r_u32(uint value,global uchar* out) {for(uint j=0;j<4;j++) out[j]=(uchar)(value>>(j*8));}
kernel void r_gather(global const uint* minimum,global const uint* invalid,
                     global const uint* fault,global const uint* lane_hits,
                     global const uchar* lane_addresses,global const uchar* endpoints,
                     uint lanes,uint count,uint family,global uchar* summary) {
#ifdef LINEAR_SEARCH
    family=1;
#endif
    uint index=minimum[0];r_u32(index,summary);r_u32(invalid[0],summary+4);r_u32(fault[0],summary+8);
    for(uint j=0;j<20;j++) summary[16+j]=0;
    uint reported=0xffffffffU;
    if(index<count*family) {
        uint lane=(index/family)%lanes;reported=lane_hits[lane];
        for(uint j=0;j<20;j++) summary[16+j]=lane_addresses[lane*20+j];
    }
    r_u32(reported,summary+12);
    for(uint j=0;j<130;j++) summary[36+j]=endpoints[j];
}
