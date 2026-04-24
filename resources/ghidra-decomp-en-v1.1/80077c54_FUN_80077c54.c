// Function: FUN_80077c54
// Entry: 80077c54
// Size: 1056 bytes

/* WARNING: Removing unreachable block (ram,0x80078050) */
/* WARNING: Removing unreachable block (ram,0x80078048) */
/* WARNING: Removing unreachable block (ram,0x80077c6c) */
/* WARNING: Removing unreachable block (ram,0x80077c64) */

void FUN_80077c54(double param_1,float *param_2,int param_3,float *param_4)

{
  undefined uVar1;
  double dVar2;
  double dVar3;
  uint3 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  int local_ac;
  undefined4 local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float afStack_98 [12];
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  
  local_b0 = DAT_803e90d4;
  FUN_80247618(param_2,param_4,&local_68);
  FUN_8025d8c4(&local_68,0x1e,1);
  FUN_80258674(0,1,0,0x1e,0,0x7d);
  FUN_8004c460((int)param_2[0x18],0);
  *(char *)(param_3 + 3) =
       (char)((int)(uint)*(byte *)(param_3 + 3) >> 1) +
       (char)((int)(uint)*(byte *)(param_3 + 3) >> 2);
  uVar1 = *(undefined *)(param_3 + 3);
  local_a8 = CONCAT13(uVar1,CONCAT12(uVar1,local_a8._2_2_));
  local_a8._2_2_ = CONCAT11(uVar1,(undefined)local_a8);
  local_b4 = local_a8;
  FUN_8025c510(0,(byte *)&local_b4);
  FUN_8025c584(0,0xc);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,8,0xe,0xf);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  local_a4 = param_4[3];
  local_a0 = param_4[7];
  local_9c = param_4[0xb];
  FUN_80247bf8(param_2 + 0xc,&local_a4,&local_a4);
  dVar3 = -(double)local_9c;
  FUN_8006c734(&local_ac);
  FUN_8004c460(local_ac,1);
  local_68 = FLOAT_803dfb5c;
  local_64 = FLOAT_803dfb5c;
  dVar2 = (double)(float)(dVar3 - (double)(float)(dVar3 - param_1));
  local_60 = (float)((double)FLOAT_803dfb64 / dVar2);
  local_5c = (float)(dVar3 / dVar2);
  local_58 = FLOAT_803dfb5c;
  local_54 = FLOAT_803dfb5c;
  local_50 = FLOAT_803dfb5c;
  local_4c = FLOAT_803dfb5c;
  FUN_80247618(param_2 + 0xc,param_4,afStack_98);
  FUN_80247618(&local_68,afStack_98,afStack_98);
  FUN_8025d8c4(afStack_98,0x21,1);
  FUN_80258674(1,1,0,0x21,0,0x7d);
  FUN_8025be80(1);
  FUN_8025c65c(1,0,0);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,0,0xf,8,0xf);
  FUN_8025c224(1,7,7,7,7);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(2);
  FUN_8025ca04(2);
  _local_b8 = local_b0;
  FUN_8025ca38((double)FLOAT_803ddca4,(double)FLOAT_803ddca0,(double)FLOAT_803ddcb8,
               (double)FLOAT_803ddcb4,4,&local_b8);
  FUN_8025cce8(1,0,3,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  return;
}

