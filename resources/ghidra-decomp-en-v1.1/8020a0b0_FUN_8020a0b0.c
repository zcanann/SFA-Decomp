// Function: FUN_8020a0b0
// Entry: 8020a0b0
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x8020a400) */
/* WARNING: Removing unreachable block (ram,0x8020a3f8) */
/* WARNING: Removing unreachable block (ram,0x8020a0c8) */
/* WARNING: Removing unreachable block (ram,0x8020a0c0) */

void FUN_8020a0b0(uint param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  if (param_1 != 0) {
    puVar4 = *(uint **)(param_1 + 0xb8);
    iVar1 = FUN_8002bac4();
    if (iVar1 != 0) {
      puVar4[1] = (uint)((float)puVar4[1] + FLOAT_803dc074);
      uVar2 = FUN_80020078(puVar4[6]);
      if ((uVar2 != 0) && ((float)puVar4[1] < FLOAT_803e7178)) {
        puVar4[1] = (uint)FLOAT_803e7190;
      }
      if (((float)puVar4[2] < (float)puVar4[1]) && ((float)puVar4[1] < FLOAT_803e7178)) {
        local_5c = *(float *)(param_1 + 0xc);
        local_58 = *(undefined4 *)(param_1 + 0x10);
        local_54 = *(float *)(param_1 + 0x14);
        if (uVar2 == 0) {
          uStack_3c = FUN_80022264(0xffffff38,200);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_68 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7188) + local_5c;
          uStack_44 = FUN_80022264(100,300);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_64 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e7188) +
                     *(float *)(param_1 + 0x10);
          uStack_4c = FUN_80022264(0xffffff38,200);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          local_60 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e7188) + local_54;
        }
        else {
          uStack_4c = FUN_80022264(0xffffff38,200);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          local_68 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e7188) +
                     *(float *)(iVar1 + 0xc);
          uStack_44 = FUN_80022264(100,300);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_64 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e7188) +
                     *(float *)(iVar1 + 0x10);
          uStack_3c = FUN_80022264(0xffffff38,200);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_60 = FLOAT_803e7194 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e7188) +
                     *(float *)(iVar1 + 0x14);
        }
        if (*puVar4 != 0) {
          FUN_800238c4(*puVar4);
          *puVar4 = 0;
        }
        dVar7 = (double)(float)puVar4[3];
        dVar6 = (double)(float)puVar4[4];
        uVar3 = FUN_80020078(0xe57);
        if (uVar3 == 0) {
          FUN_8000b4f0(param_1,0x4c3,2);
          if (uVar2 == 0) {
            dVar5 = (double)FLOAT_803e7198;
            if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e719c < dVar6)) {
              dVar5 = (double)FLOAT_803e719c;
            }
            dVar6 = (double)FLOAT_803e7198;
            if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)FLOAT_803e719c < dVar7)) {
              dVar6 = (double)FLOAT_803e719c;
            }
            uVar2 = FUN_8008fdac(dVar6,dVar5,&local_5c,&local_68,*(undefined2 *)((int)puVar4 + 0x16)
                                 ,(char)*(undefined2 *)(puVar4 + 5) * '\f',0);
            *puVar4 = uVar2;
          }
          else {
            dVar5 = (double)FLOAT_803e7198;
            if ((dVar5 <= dVar6) && (dVar5 = dVar6, (double)FLOAT_803e719c < dVar6)) {
              dVar5 = (double)FLOAT_803e719c;
            }
            dVar6 = (double)FLOAT_803e7198;
            if ((dVar6 <= dVar7) && (dVar6 = dVar7, (double)FLOAT_803e719c < dVar7)) {
              dVar6 = (double)FLOAT_803e719c;
            }
            uVar2 = FUN_8008fdac(dVar6,dVar5,&local_5c,&local_68,10,
                                 (char)*(undefined2 *)(puVar4 + 5) * '\f',0);
            *puVar4 = uVar2;
          }
        }
        puVar4[1] = (uint)FLOAT_803e7178;
      }
    }
  }
  return;
}

