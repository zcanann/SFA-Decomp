// Function: FUN_8011f234
// Entry: 8011f234
// Size: 768 bytes

/* WARNING: Removing unreachable block (ram,0x8011f50c) */
/* WARNING: Removing unreachable block (ram,0x8011f244) */

void FUN_8011f234(double param_1,double param_2,double param_3,double param_4,ushort param_5,
                 ushort param_6,ushort param_7)

{
  double dVar1;
  float afStack_98 [12];
  float afStack_68 [12];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  FLOAT_803de498 = (float)param_1;
  FLOAT_803de494 = (float)param_2;
  FLOAT_803de490 = (float)param_3;
  FLOAT_803de48c = (float)param_4;
  uStack_34 = (uint)param_5;
  local_38 = 0x43300000;
  FLOAT_803de488 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  uStack_2c = (uint)param_6;
  local_30 = 0x43300000;
  FLOAT_803de484 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  uStack_24 = (uint)param_7;
  local_28 = 0x43300000;
  FLOAT_803de480 =
       (FLOAT_803e2b10 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e2b08)) /
       FLOAT_803e2b14;
  FUN_8024782c((double)FLOAT_803de480,afStack_68,0x79);
  FUN_8024782c((double)FLOAT_803de484,afStack_98,0x78);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  FUN_8024782c((double)FLOAT_803de488,afStack_98,0x7a);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  dVar1 = (double)FLOAT_803de48c;
  FUN_80247a7c(dVar1,dVar1,dVar1,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_68);
  FUN_80247a48((double)FLOAT_803de498,(double)FLOAT_803de494,(double)FLOAT_803de490,afStack_98);
  FUN_80247618(afStack_98,afStack_68,(float *)&DAT_803a95b0);
  FUN_80247a7c((double)FLOAT_803dc76c,-(double)FLOAT_803dc770,(double)FLOAT_803dc774,afStack_68);
  FUN_80247a48((double)FLOAT_803e2b18,(double)FLOAT_803e2ae8,(double)FLOAT_803e2abc,afStack_98);
  FUN_80247618(afStack_98,afStack_68,afStack_98);
  FUN_80247618((float *)&DAT_803a95b0,afStack_98,(float *)&DAT_803a9490);
  FUN_80247d2c((double)FLOAT_803dc75c,(double)FLOAT_803dc760,(double)FLOAT_803dc764,
               (double)FLOAT_803dc768,(float *)&DAT_803a9450);
  dVar1 = FUN_8000fc54();
  FLOAT_803de47c = (float)dVar1;
  FUN_8000fc5c((double)FLOAT_803dc75c);
  FUN_8000fb20();
  FUN_8000f478(1);
  dVar1 = (double)FLOAT_803e2abc;
  FUN_8000f530(dVar1,dVar1,dVar1);
  FUN_8000f500(0x8000,0,0);
  FUN_8000f584();
  *(float *)(DAT_803de4e0 + 6) = FLOAT_803de498;
  *(float *)(DAT_803de4e0 + 8) = FLOAT_803de494;
  *(float *)(DAT_803de4e0 + 10) = FLOAT_803de490;
  *(float *)(DAT_803de4e0 + 0xc) = FLOAT_803de498;
  *(float *)(DAT_803de4e0 + 0xe) = FLOAT_803de494;
  *(float *)(DAT_803de4e0 + 0x10) = FLOAT_803de490;
  *(float *)(DAT_803de4e0 + 4) = (float)param_4;
  DAT_803de4e0[2] = param_5;
  DAT_803de4e0[1] = param_6;
  *DAT_803de4e0 = param_7;
  *(float *)(puRam803de4e4 + 6) = FLOAT_803de498;
  *(float *)(puRam803de4e4 + 8) = FLOAT_803de494;
  *(float *)(puRam803de4e4 + 10) = FLOAT_803de490;
  *(float *)(puRam803de4e4 + 0xc) = FLOAT_803de498;
  *(float *)(puRam803de4e4 + 0xe) = FLOAT_803de494;
  *(float *)(puRam803de4e4 + 0x10) = FLOAT_803de490;
  *(float *)(puRam803de4e4 + 4) = (float)param_4;
  puRam803de4e4[2] = param_5;
  puRam803de4e4[1] = param_6;
  *puRam803de4e4 = param_7;
  return;
}

