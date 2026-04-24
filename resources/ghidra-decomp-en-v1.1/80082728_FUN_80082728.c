// Function: FUN_80082728
// Entry: 80082728
// Size: 1588 bytes

/* WARNING: Removing unreachable block (ram,0x80082d34) */
/* WARNING: Removing unreachable block (ram,0x80082d2c) */
/* WARNING: Removing unreachable block (ram,0x80082d24) */
/* WARNING: Removing unreachable block (ram,0x80082748) */
/* WARNING: Removing unreachable block (ram,0x80082740) */
/* WARNING: Removing unreachable block (ram,0x80082738) */

void FUN_80082728(void)

{
  short sVar1;
  short sVar2;
  short sVar3;
  short *psVar4;
  undefined4 *puVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  int iStack_1a8;
  int local_1a4;
  undefined local_1a0;
  int local_19c;
  undefined local_198;
  float local_194;
  float local_190;
  undefined2 local_18c;
  short local_188;
  short local_186;
  short local_184;
  float local_17c;
  float local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_d4;
  
  if (DAT_803ddd38 == (short *)0x0) {
    if (DAT_803ddd90 == '\0') {
      DAT_803ddd88 = 1;
      DAT_803ddd80 = 0x5a;
      DAT_803ddd8c = 0x42;
    }
    else {
      if (DAT_803ddce4 == 0) {
        switch(DAT_803ddd8c) {
        case 0x44:
          if (DAT_803ddd88 == 0) {
            local_194 = FLOAT_803dfc74;
            local_190 = FLOAT_803dfc78;
            local_18c = 0x1e;
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x44,1,0,0xc,&local_194,0,0xff);
          }
          else {
            local_194 = FLOAT_803dfc74;
            local_190 = FLOAT_803dfc78;
            local_18c = 5;
            (**(code **)(*DAT_803dd6d0 + 0x1c))(0x44,1,1,0xc,&local_194,0,0xff);
          }
          break;
        case 0x45:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x45,1,0,0,0,DAT_803ddd80,0xff);
          break;
        default:
          if (DAT_803ddd88 == 0) {
            DAT_803ddd88 = 1;
          }
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,DAT_803ddd88,0,0,DAT_803ddd80,0xff);
          break;
        case 0x47:
          local_19c = DAT_803ddd88;
          local_198 = (undefined)DAT_803ddd84;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x47,1,3,8,&local_19c,DAT_803ddd80,0xff);
          break;
        case 0x48:
          local_1a4 = DAT_803ddd88;
          if (DAT_803ddd80 == 0) {
            local_1a0 = 1;
          }
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x48,1,3,8,&local_1a4,DAT_803ddd80,0xff);
          break;
        case 0x49:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x49,1,0,DAT_803ddd88,&DAT_803ddd84,DAT_803ddd80,0xff)
          ;
          break;
        case 0x4a:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4a,1,0,0,0,DAT_803ddd80,0xff);
          break;
        case 0x4c:
          local_17c = FLOAT_803ddd30;
          local_178 = FLOAT_803ddd2c;
          local_174 = FLOAT_803ddd28;
          local_188 = (short)DAT_803ddd20;
          local_186 = (short)DAT_803ddd1c;
          local_184 = (short)DAT_803ddd18;
          local_d4 = FLOAT_803ddd24;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4c,1,0,0x144,&local_188,0,0xff);
          break;
        case 0x53:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x53,1,0,0,0,0,0xff);
          break;
        case 0x56:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x56,1,DAT_803ddd88,0,0,0,0);
          break;
        case 0x57:
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x57,0,3,0,0,0,0);
          puVar5 = FUN_80037048(0xf,&iStack_1a8);
          (**(code **)(*DAT_803dd6d0 + 0x28))(*puVar5,0);
        }
      }
      DAT_803ddd90 = '\0';
      FLOAT_803dc370 = FLOAT_803dfc7c;
      DAT_803ddd88 = 1;
      DAT_803ddd80 = 0x5a;
      DAT_803ddd8c = 0x42;
      DAT_803ddd0c = 0;
    }
  }
  else {
    local_168 = FLOAT_803ddd6c;
    local_16c = FLOAT_803ddd70;
    local_170 = FLOAT_803ddd74;
    if (DAT_803ddd78 == '\0') {
      local_168 = *(float *)(DAT_803ddd38 + 0x10);
      local_16c = *(float *)(DAT_803ddd38 + 0xe);
      local_170 = *(float *)(DAT_803ddd38 + 0xc);
    }
    dVar8 = (double)local_170;
    dVar7 = (double)local_16c;
    dVar6 = (double)local_168;
    sVar3 = *DAT_803ddd38;
    sVar1 = DAT_803ddd38[1];
    sVar2 = DAT_803ddd38[2];
    if (*(short **)(DAT_803ddd38 + 0x18) != (short *)0x0) {
      sVar3 = sVar3 + **(short **)(DAT_803ddd38 + 0x18);
    }
    FLOAT_803ddd5c = FLOAT_803dfc48;
    if (DAT_803ddd90 == '\0') {
      local_188 = -0x8000 - sVar3;
      local_186 = -sVar1;
      if (DAT_803ddd08 == '\0') {
        local_d4 = FLOAT_803dc370;
      }
      else {
        local_d4 = FLOAT_803ddd50;
      }
      FLOAT_803dc370 = local_d4;
      local_184 = sVar2;
      (**(code **)(*DAT_803dd6d0 + 0x1c))
                (0x4c,0,1,0x144,&local_188,*(undefined *)(*(int *)(DAT_803ddd38 + 0x26) + 0x24),0xff
                );
      DAT_803ddd90 = '\x01';
    }
    else {
      psVar4 = (short *)(**(code **)(*DAT_803dd6d0 + 0xc))();
      *(float *)(psVar4 + 0xc) = (float)dVar8;
      *(float *)(psVar4 + 0xe) = (float)dVar7;
      *(float *)(psVar4 + 0x10) = (float)dVar6;
      FUN_8000e054((double)*(float *)(psVar4 + 0xc),(double)*(float *)(psVar4 + 0xe),
                   (double)*(float *)(psVar4 + 0x10),(float *)(psVar4 + 6),(float *)(psVar4 + 8),
                   (float *)(psVar4 + 10),*(int *)(psVar4 + 0x18));
      *psVar4 = -0x8000 - sVar3;
      psVar4[1] = -sVar1;
      psVar4[2] = sVar2;
      if (DAT_803ddd08 == '\0') {
        *(float *)(psVar4 + 0x5a) = FLOAT_803dc370;
      }
      else {
        *(float *)(psVar4 + 0x5a) = FLOAT_803ddd50;
        FLOAT_803dc370 = FLOAT_803ddd50;
      }
      FLOAT_803ddd30 = *(float *)(psVar4 + 0xc);
      FLOAT_803ddd2c = *(float *)(psVar4 + 0xe);
      FLOAT_803ddd28 = *(float *)(psVar4 + 0x10);
      DAT_803ddd20 = (int)*psVar4;
      DAT_803ddd1c = (int)psVar4[1];
      DAT_803ddd18 = (int)psVar4[2];
      FLOAT_803ddd24 = *(float *)(psVar4 + 0x5a);
    }
  }
  DAT_803ddd08 = 0;
  DAT_803ddd38 = (short *)0x0;
  DAT_803ddd78 = 0;
  return;
}

