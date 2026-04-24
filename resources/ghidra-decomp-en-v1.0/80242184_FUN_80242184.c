// Function: FUN_80242184
// Entry: 80242184
// Size: 296 bytes

void FUN_80242184(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  byte in_fp_fx;
  byte in_fp_fex;
  byte in_fp_vx;
  byte in_fp_ox;
  byte in_fp_ux;
  byte in_fp_zx;
  byte in_fp_xx;
  byte in_fp_vxsnan;
  byte in_fp_vxisi;
  byte in_fp_vxidi;
  byte in_fp_vxzdz;
  byte in_fp_vximz;
  byte in_fp_vxvc;
  byte in_fp_fr;
  byte in_fp_fi;
  byte in_fp_c;
  byte in_fp_cc0;
  byte in_fp_cc1;
  byte in_fp_cc2;
  byte in_fp_cc3;
  byte in_fp_reserve1;
  byte in_fp_vxsoft;
  byte in_fp_vxsqrt;
  byte in_fp_vxcvi;
  byte in_fp_ve;
  byte in_fp_oe;
  byte in_fp_ue;
  byte in_fp_ze;
  byte in_fp_xe;
  byte in_fp_ni;
  byte in_fp_rn0;
  byte in_fp_rn1;
  uint in_HID2;
  undefined8 in_f0;
  undefined4 in_ps9_0;
  undefined4 in_ps9_1;
  undefined4 in_ps10_0;
  undefined4 in_ps10_1;
  undefined4 in_ps11_0;
  undefined4 in_ps11_1;
  undefined4 in_ps12_0;
  undefined4 in_ps12_1;
  undefined4 in_ps13_0;
  undefined4 in_ps13_1;
  undefined4 in_ps14_0;
  undefined4 in_ps14_1;
  undefined4 in_ps15_0;
  undefined4 in_ps15_1;
  undefined4 in_ps16_0;
  undefined4 in_ps16_1;
  undefined4 in_ps17_0;
  undefined4 in_ps17_1;
  undefined4 in_ps18_0;
  undefined4 in_ps18_1;
  undefined4 in_ps19_0;
  undefined4 in_ps19_1;
  undefined4 in_ps20_0;
  undefined4 in_ps20_1;
  undefined4 in_ps21_0;
  undefined4 in_ps21_1;
  undefined4 in_ps22_0;
  undefined4 in_ps22_1;
  undefined4 in_ps23_0;
  undefined4 in_ps23_1;
  undefined4 in_ps24_0;
  undefined4 in_ps24_1;
  undefined4 in_ps25_0;
  undefined4 in_ps25_1;
  undefined4 in_ps26_0;
  undefined4 in_ps26_1;
  undefined4 in_ps27_0;
  undefined4 in_ps27_1;
  undefined4 in_ps28_0;
  undefined4 in_ps28_1;
  undefined4 in_ps29_0;
  undefined4 in_ps29_1;
  undefined4 in_ps30_0;
  undefined4 in_ps30_1;
  undefined4 in_ps31_0;
  undefined4 in_ps31_1;
  
  *(ushort *)(param_11 + 0x1a2) = *(ushort *)(param_11 + 0x1a2) | 1;
  *(undefined8 *)(param_11 + 0x90) = in_f0;
  *(undefined8 *)(param_11 + 0x98) = param_1;
  *(undefined8 *)(param_11 + 0xa0) = param_2;
  *(undefined8 *)(param_11 + 0xa8) = param_3;
  *(undefined8 *)(param_11 + 0xb0) = param_4;
  *(undefined8 *)(param_11 + 0xb8) = param_5;
  *(undefined8 *)(param_11 + 0xc0) = param_6;
  *(undefined8 *)(param_11 + 200) = param_7;
  *(undefined8 *)(param_11 + 0xd0) = param_8;
  *(ulonglong *)(param_11 + 0xd8) = CONCAT44(in_ps9_0,in_ps9_1);
  *(ulonglong *)(param_11 + 0xe0) = CONCAT44(in_ps10_0,in_ps10_1);
  *(ulonglong *)(param_11 + 0xe8) = CONCAT44(in_ps11_0,in_ps11_1);
  *(ulonglong *)(param_11 + 0xf0) = CONCAT44(in_ps12_0,in_ps12_1);
  *(ulonglong *)(param_11 + 0xf8) = CONCAT44(in_ps13_0,in_ps13_1);
  *(ulonglong *)(param_11 + 0x100) = CONCAT44(in_ps14_0,in_ps14_1);
  *(ulonglong *)(param_11 + 0x108) = CONCAT44(in_ps15_0,in_ps15_1);
  *(ulonglong *)(param_11 + 0x110) = CONCAT44(in_ps16_0,in_ps16_1);
  *(ulonglong *)(param_11 + 0x118) = CONCAT44(in_ps17_0,in_ps17_1);
  *(ulonglong *)(param_11 + 0x120) = CONCAT44(in_ps18_0,in_ps18_1);
  *(ulonglong *)(param_11 + 0x128) = CONCAT44(in_ps19_0,in_ps19_1);
  *(ulonglong *)(param_11 + 0x130) = CONCAT44(in_ps20_0,in_ps20_1);
  *(ulonglong *)(param_11 + 0x138) = CONCAT44(in_ps21_0,in_ps21_1);
  *(ulonglong *)(param_11 + 0x140) = CONCAT44(in_ps22_0,in_ps22_1);
  *(ulonglong *)(param_11 + 0x148) = CONCAT44(in_ps23_0,in_ps23_1);
  *(ulonglong *)(param_11 + 0x150) = CONCAT44(in_ps24_0,in_ps24_1);
  *(ulonglong *)(param_11 + 0x158) = CONCAT44(in_ps25_0,in_ps25_1);
  *(ulonglong *)(param_11 + 0x160) = CONCAT44(in_ps26_0,in_ps26_1);
  *(ulonglong *)(param_11 + 0x168) = CONCAT44(in_ps27_0,in_ps27_1);
  *(ulonglong *)(param_11 + 0x170) = CONCAT44(in_ps28_0,in_ps28_1);
  *(ulonglong *)(param_11 + 0x178) = CONCAT44(in_ps29_0,in_ps29_1);
  *(ulonglong *)(param_11 + 0x180) = CONCAT44(in_ps30_0,in_ps30_1);
  *(ulonglong *)(param_11 + 0x188) = CONCAT44(in_ps31_0,in_ps31_1);
  *(ulonglong *)(param_11 + 400) =
       (ulonglong)
       (in_fp_rn1 & 1 | (uint)in_fp_fx << 0x1f | (in_fp_fex & 1) << 0x1e | (in_fp_vx & 1) << 0x1d |
        (in_fp_ox & 1) << 0x1c | (in_fp_ux & 1) << 0x1b | (in_fp_zx & 1) << 0x1a |
        (in_fp_xx & 1) << 0x19 | (in_fp_vxsnan & 1) << 0x18 | (in_fp_vxisi & 1) << 0x17 |
        (in_fp_vxidi & 1) << 0x16 | (in_fp_vxzdz & 1) << 0x15 | (in_fp_vximz & 1) << 0x14 |
        (in_fp_vxvc & 1) << 0x13 | (in_fp_fr & 1) << 0x12 | (in_fp_fi & 1) << 0x11 |
        (in_fp_c & 1) << 0x10 | (in_fp_cc0 & 1) << 0xf | (in_fp_cc1 & 1) << 0xe |
        (in_fp_cc2 & 1) << 0xd | (in_fp_cc3 & 1) << 0xc | (in_fp_reserve1 & 1) << 0xb |
        (in_fp_vxsoft & 1) << 10 | (in_fp_vxsqrt & 1) << 9 | (in_fp_vxcvi & 1) << 8 |
        (in_fp_ve & 1) << 7 | (in_fp_oe & 1) << 6 | (in_fp_ue & 1) << 5 | (in_fp_ze & 1) << 4 |
        (in_fp_xe & 1) << 3 | (in_fp_ni & 1) << 2 | (in_fp_rn0 & 1) << 1);
  if ((in_HID2 >> 0x1d & 1) != 0) {
    __psq_st0(param_11 + 0x1c8,(int)((ulonglong)*(undefined8 *)(param_11 + 0x90) >> 0x20),0);
    __psq_st1(param_11 + 0x1c8,(int)*(undefined8 *)(param_11 + 0x90),0);
    __psq_st0(param_11 + 0x1d0,(int)((ulonglong)param_1 >> 0x20),0);
    __psq_st1(param_11 + 0x1d0,(int)param_1,0);
    __psq_st0(param_11 + 0x1d8,(int)((ulonglong)param_2 >> 0x20),0);
    __psq_st1(param_11 + 0x1d8,(int)param_2,0);
    __psq_st0(param_11 + 0x1e0,(int)((ulonglong)param_3 >> 0x20),0);
    __psq_st1(param_11 + 0x1e0,(int)param_3,0);
    __psq_st0(param_11 + 0x1e8,(int)((ulonglong)param_4 >> 0x20),0);
    __psq_st1(param_11 + 0x1e8,(int)param_4,0);
    __psq_st0(param_11 + 0x1f0,(int)((ulonglong)param_5 >> 0x20),0);
    __psq_st1(param_11 + 0x1f0,(int)param_5,0);
    __psq_st0(param_11 + 0x1f8,(int)((ulonglong)param_6 >> 0x20),0);
    __psq_st1(param_11 + 0x1f8,(int)param_6,0);
    __psq_st0(param_11 + 0x200,(int)((ulonglong)param_7 >> 0x20),0);
    __psq_st1(param_11 + 0x200,(int)param_7,0);
    __psq_st0(param_11 + 0x208,(int)((ulonglong)param_8 >> 0x20),0);
    __psq_st1(param_11 + 0x208,(int)param_8,0);
    __psq_st0(param_11 + 0x210,in_ps9_0,0);
    __psq_st1(param_11 + 0x210,in_ps9_1,0);
    __psq_st0(param_11 + 0x218,in_ps10_0,0);
    __psq_st1(param_11 + 0x218,in_ps10_1,0);
    __psq_st0(param_11 + 0x220,in_ps11_0,0);
    __psq_st1(param_11 + 0x220,in_ps11_1,0);
    __psq_st0(param_11 + 0x228,in_ps12_0,0);
    __psq_st1(param_11 + 0x228,in_ps12_1,0);
    __psq_st0(param_11 + 0x230,in_ps13_0,0);
    __psq_st1(param_11 + 0x230,in_ps13_1,0);
    __psq_st0(param_11 + 0x238,in_ps14_0,0);
    __psq_st1(param_11 + 0x238,in_ps14_1,0);
    __psq_st0(param_11 + 0x240,in_ps15_0,0);
    __psq_st1(param_11 + 0x240,in_ps15_1,0);
    __psq_st0(param_11 + 0x248,in_ps16_0,0);
    __psq_st1(param_11 + 0x248,in_ps16_1,0);
    __psq_st0(param_11 + 0x250,in_ps17_0,0);
    __psq_st1(param_11 + 0x250,in_ps17_1,0);
    __psq_st0(param_11 + 600,in_ps18_0,0);
    __psq_st1(param_11 + 600,in_ps18_1,0);
    __psq_st0(param_11 + 0x260,in_ps19_0,0);
    __psq_st1(param_11 + 0x260,in_ps19_1,0);
    __psq_st0(param_11 + 0x268,in_ps20_0,0);
    __psq_st1(param_11 + 0x268,in_ps20_1,0);
    __psq_st0(param_11 + 0x270,in_ps21_0,0);
    __psq_st1(param_11 + 0x270,in_ps21_1,0);
    __psq_st0(param_11 + 0x278,in_ps22_0,0);
    __psq_st1(param_11 + 0x278,in_ps22_1,0);
    __psq_st0(param_11 + 0x280,in_ps23_0,0);
    __psq_st1(param_11 + 0x280,in_ps23_1,0);
    __psq_st0(param_11 + 0x288,in_ps24_0,0);
    __psq_st1(param_11 + 0x288,in_ps24_1,0);
    __psq_st0(param_11 + 0x290,in_ps25_0,0);
    __psq_st1(param_11 + 0x290,in_ps25_1,0);
    __psq_st0(param_11 + 0x298,in_ps26_0,0);
    __psq_st1(param_11 + 0x298,in_ps26_1,0);
    __psq_st0(param_11 + 0x2a0,in_ps27_0,0);
    __psq_st1(param_11 + 0x2a0,in_ps27_1,0);
    __psq_st0(param_11 + 0x2a8,in_ps28_0,0);
    __psq_st1(param_11 + 0x2a8,in_ps28_1,0);
    __psq_st0(param_11 + 0x2b0,in_ps29_0,0);
    __psq_st1(param_11 + 0x2b0,in_ps29_1,0);
    __psq_st0(param_11 + 0x2b8,in_ps30_0,0);
    __psq_st1(param_11 + 0x2b8,in_ps30_1,0);
    __psq_st0(param_11 + 0x2c0,in_ps31_0,0);
    __psq_st1(param_11 + 0x2c0,in_ps31_1,0);
  }
  return;
}

