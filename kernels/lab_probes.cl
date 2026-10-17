/* Optional developer-tools public hash/matcher/reduction probes. */
/* Public fixed-64-byte Keccak diagnostics. Non-EVM builds rename the shared
 * hash entry point; omit this EVM-only probe in those builds. */
#ifndef CH_HASH
kernel void ethereum_hash_probe(global const uchar* coordinates,global uchar* addresses,uint count){
    uint id=(uint)get_global_id(0);if(id>=count)return;
    fe x=load_fe(coordinates+id*64),y=load_fe(coordinates+id*64+32);
    uchar out[20];eth_address(x,y,out);
    for(uint i=0;i<20;i++)addresses[id*20+i]=out[i];
}
#endif

/* Original MIT public-vector matcher qualification. Append to field_probe.cl.
 * Input records: address20 || existing wire492 || prefix_le32 || suffix_le32.
 * This diagnostic intentionally accepts raw masks for mutation checks. Production
 * job matching still receives only the canonical host-generated pattern wire. */
#if defined(WORD_MATCH) && defined(ADDRESS_KECCAK) && !defined(CH_HASH)
kernel void ethereum_word_match_probe(global const uchar* records,global uint* decisions,uint count) {
    uint id=(uint)get_global_id(0);if(id>=count)return;
    global const uchar* record=records+id*520;
    global const uchar* pattern=record+20;
    uint prefix=eth_pattern_u32(record+512),suffix=eth_pattern_u32(record+516);
    eth_payload_words words;
    words.w0=eth_pattern_u32(record);words.w1=eth_pattern_u32(record+4);
    words.w2=eth_pattern_u32(record+8);words.w3=eth_pattern_u32(record+12);
    words.w4=eth_pattern_u32(record+16);
    uchar original[20],roundtrip[20];
    for(uint i=0;i<20;i++)original[i]=record[i];
    eth_words_bytes(words,roundtrip);
    uint different=0;for(uint i=0;i<20;i++)different|=(uint)(roundtrip[i]^original[i]);
    decisions[id*3]=(uint)matching(original,pattern,prefix,suffix);
    decisions[id*3+1]=(uint)eth_words_matching(words,pattern,prefix,suffix);
    decisions[id*3+2]=(uint)(different==0);
}
kernel void ethereum_word_hash_probe(global const uchar* coordinates,global uchar* addresses,uint count) {
    uint id=(uint)get_global_id(0);if(id>=count)return;
    eth_payload_words words=eth_address_words(load_fe(coordinates+id*64),load_fe(coordinates+id*64+32));
    uchar address[20];eth_words_bytes(words,address);
    for(uint i=0;i<20;i++)addresses[id*20+i]=address[i];
}
#endif

/* Raw 512-bit synthetic public integers: deliberately not canonical field
 * operands. Independent vectors exercise reduction beyond product-only cases. */
#ifdef BOUNDED_MULTIPLY
kernel void field_reduce512_probe(global const uint* inputs,uint count,global uint* outputs) {
    uint id=(uint)get_global_id(0);if(id>=count)return;
    uint wide[16];for(uint i=0;i<16;i++)wide[i]=inputs[id*16+i];
    fe result=bounded_reduce512(wide[0],wide[1],wide[2],wide[3],wide[4],wide[5],wide[6],wide[7],wide[8],wide[9],wide[10],wide[11],wide[12],wide[13],wide[14],wide[15]);
    for(uint i=0;i<8;i++)outputs[id*8+i]=result.v[i];
}
#endif
