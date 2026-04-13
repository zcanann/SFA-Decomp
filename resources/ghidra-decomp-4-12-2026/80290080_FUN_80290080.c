// Function: FUN_80290080
// Entry: 80290080
// Size: 1908 bytes

/* WARNING: Type propagation algorithm not settling */

int FUN_80290080(undefined *param_1,undefined4 param_2,char *param_3,char *param_4)

{
  byte bVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  double *pdVar6;
  uint uVar7;
  char *pcVar8;
  int *piVar9;
  ushort *puVar10;
  byte *pbVar11;
  uint unaff_r22;
  uint unaff_r23;
  char *pcVar12;
  char *pcVar13;
  int iVar14;
  uint unaff_r28;
  double dVar15;
  undefined local_2b8;
  char local_2b7 [3];
  uint local_2b4;
  undefined4 local_2b0;
  int local_2ac;
  char *local_2a8;
  uint local_2a4;
  undefined4 local_2a0;
  int local_29c;
  char *local_298;
  uint local_294;
  undefined4 local_290;
  int local_28c;
  char *local_288;
  uint local_284;
  undefined4 local_280;
  int local_27c;
  char *local_278;
  uint local_274;
  undefined4 local_270;
  int local_26c;
  char *local_268;
  uint local_264;
  undefined4 local_260;
  int local_25c;
  char *local_258;
  undefined4 local_254;
  undefined4 local_250;
  int local_24c;
  char *local_248;
  byte local_244 [511];
  char acStack_45 [17];
  
  pcVar12 = acStack_45 + 1;
  iVar14 = 0;
  local_2b7[0] = ' ';
LAB_802907d0:
  if (*param_3 == '\0') {
    return iVar14;
  }
  pcVar2 = FUN_80291d44((int)param_3,'%');
  if (pcVar2 == (char *)0x0) {
    iVar3 = FUN_80292004((int)param_3);
    if (iVar3 == 0) {
      return iVar14 + iVar3;
    }
    iVar4 = (*(code *)param_1)(param_2,param_3);
    if (iVar4 != 0) {
      return iVar14 + iVar3;
    }
    return -1;
  }
  iVar14 = iVar14 + ((int)pcVar2 - (int)param_3);
  if (((int)pcVar2 - (int)param_3 != 0) && (iVar3 = (*(code *)param_1)(param_2,param_3), iVar3 == 0)
     ) {
    return -1;
  }
  param_3 = FUN_80291840((int)pcVar2,param_4,&local_254);
  if (local_250._1_1_ == 0x68) goto LAB_80290650;
  if (local_250._1_1_ < 0x68) {
    if (local_250._1_1_ == 0x58) goto LAB_8029030c;
    if (local_250._1_1_ < 0x58) {
      if (local_250._1_1_ == 0x41) {
LAB_80290474:
        if (local_250._0_1_ == '\x05') {
          pdVar6 = (double *)FUN_80286608(param_4,3);
          dVar15 = *pdVar6;
        }
        else {
          pdVar6 = (double *)FUN_80286608(param_4,3);
          dVar15 = *pdVar6;
        }
        local_2b4 = local_254;
        local_2b0 = local_250;
        local_2ac = local_24c;
        local_2a8 = local_248;
        pbVar11 = (byte *)FUN_8029100c(dVar15,(int)pcVar12,(int)&local_2b4);
        if (pbVar11 == (byte *)0x0) goto LAB_80290650;
        pcVar2 = acStack_45 + -(int)pbVar11;
      }
      else {
        if (0x40 < local_250._1_1_) {
          if ((0x47 < local_250._1_1_) || (local_250._1_1_ < 0x45)) goto LAB_80290650;
          goto LAB_80290408;
        }
        if (local_250._1_1_ != 0x25) goto LAB_80290650;
        pbVar11 = local_244;
        local_244[0] = 0x25;
        pcVar2 = (char *)0x1;
      }
    }
    else if (local_250._1_1_ == 99) {
      pbVar11 = local_244;
      piVar9 = FUN_80286608(param_4,1);
      local_244[0] = (byte)*piVar9;
      pcVar2 = (char *)0x1;
    }
    else {
      if (local_250._1_1_ < 99) {
        if (local_250._1_1_ != 0x61) goto LAB_80290650;
        goto LAB_80290474;
      }
      if (local_250._1_1_ < 0x65) goto LAB_80290210;
LAB_80290408:
      if (local_250._0_1_ == '\x05') {
        pdVar6 = (double *)FUN_80286608(param_4,3);
        dVar15 = *pdVar6;
      }
      else {
        pdVar6 = (double *)FUN_80286608(param_4,3);
        dVar15 = *pdVar6;
      }
      local_2a4 = local_254;
      local_2a0 = local_250;
      local_29c = local_24c;
      local_298 = local_248;
      pbVar11 = FUN_802907f4(dVar15,(int)pcVar12,(int)&local_2a4);
      if (pbVar11 == (byte *)0x0) goto LAB_80290650;
      pcVar2 = acStack_45 + -(int)pbVar11;
    }
  }
  else {
    if (local_250._1_1_ == 0x74) goto LAB_80290650;
    if (local_250._1_1_ < 0x74) {
      if (local_250._1_1_ != 0x6f) {
        if (local_250._1_1_ < 0x6f) {
          if (local_250._1_1_ < 0x6e) {
            if (0x69 < local_250._1_1_) goto LAB_80290650;
LAB_80290210:
            if (local_250._0_1_ == '\x03') {
              puVar5 = (uint *)FUN_80286608(param_4,1);
              unaff_r28 = *puVar5;
            }
            else if (local_250._0_1_ == '\x04') {
              puVar5 = (uint *)FUN_80286608(param_4,2);
              unaff_r22 = *puVar5;
              unaff_r23 = puVar5[1];
            }
            else {
              puVar5 = (uint *)FUN_80286608(param_4,1);
              unaff_r28 = *puVar5;
            }
            if (local_250._0_1_ == '\x02') {
              unaff_r28 = (uint)(short)unaff_r28;
            }
            if (local_250._0_1_ == '\x01') {
              unaff_r28 = (uint)(char)unaff_r28;
            }
            if (local_250._0_1_ == '\x04') {
              local_264 = local_254;
              local_260 = local_250;
              local_25c = local_24c;
              local_258 = local_248;
              pbVar11 = (byte *)FUN_80291344(unaff_r22,unaff_r23,(int)pcVar12,(char *)&local_264);
            }
            else {
              local_274 = local_254;
              local_270 = local_250;
              local_26c = local_24c;
              local_268 = local_248;
              pbVar11 = (byte *)FUN_80291620(unaff_r28,(int)pcVar12,(char *)&local_274);
            }
            if (pbVar11 == (byte *)0x0) goto LAB_80290650;
            pcVar2 = acStack_45 + -(int)pbVar11;
            goto LAB_80290690;
          }
          piVar9 = FUN_80286608(param_4,1);
          piVar9 = (int *)*piVar9;
          if (local_250._0_1_ == 2) {
            *(short *)piVar9 = (short)iVar14;
          }
          else if (local_250._0_1_ < 2) {
            if (local_250._0_1_ == 0) {
              *piVar9 = iVar14;
            }
          }
          else if (local_250._0_1_ == 4) {
            piVar9[1] = iVar14;
            *piVar9 = iVar14 >> 0x1f;
          }
          else if (local_250._0_1_ < 4) {
            *piVar9 = iVar14;
          }
          goto LAB_802907d0;
        }
        if (local_250._1_1_ < 0x73) goto LAB_80290650;
        if (local_250._0_1_ == '\x06') {
          piVar9 = FUN_80286608(param_4,1);
          puVar10 = (ushort *)*piVar9;
          if (puVar10 == (ushort *)0x0) {
            puVar10 = (ushort *)&DAT_803dd2a8;
          }
          uVar7 = FUN_8028f844((int)local_244,puVar10,0x200);
          if ((int)uVar7 < 0) goto LAB_80290650;
          pbVar11 = local_244;
        }
        else {
          piVar9 = FUN_80286608(param_4,1);
          pbVar11 = (byte *)*piVar9;
        }
        pcVar13 = local_248;
        if (pbVar11 == (byte *)0x0) {
          pbVar11 = &DAT_802c3278;
        }
        if ((char)local_254 == '\0') {
          if (local_254._2_1_ == '\0') {
            pcVar2 = (char *)FUN_80292004((int)pbVar11);
          }
          else {
            pcVar8 = FUN_8028fa00((int)pbVar11,'\0',(int)local_248);
            pcVar2 = pcVar13;
            if (pcVar8 != (char *)0x0) {
              pcVar2 = pcVar8 + -(int)pbVar11;
            }
          }
        }
        else {
          pcVar2 = (char *)(uint)*pbVar11;
          pbVar11 = pbVar11 + 1;
          if ((local_254._2_1_ != '\0') && ((int)local_248 < (int)pcVar2)) {
            pcVar2 = pcVar13;
          }
        }
        goto LAB_80290690;
      }
    }
    else if ((local_250._1_1_ != 0x78) && ((0x77 < local_250._1_1_ || (0x75 < local_250._1_1_))))
    goto LAB_80290650;
LAB_8029030c:
    if (local_250._0_1_ == '\x03') {
      puVar5 = (uint *)FUN_80286608(param_4,1);
      unaff_r28 = *puVar5;
    }
    else if (local_250._0_1_ == '\x04') {
      puVar5 = (uint *)FUN_80286608(param_4,2);
      unaff_r22 = *puVar5;
      unaff_r23 = puVar5[1];
    }
    else {
      puVar5 = (uint *)FUN_80286608(param_4,1);
      unaff_r28 = *puVar5;
    }
    if (local_250._0_1_ == '\x02') {
      unaff_r28 = unaff_r28 & 0xffff;
    }
    if (local_250._0_1_ == '\x01') {
      unaff_r28 = unaff_r28 & 0xff;
    }
    if (local_250._0_1_ == '\x04') {
      local_284 = local_254;
      local_280 = local_250;
      local_27c = local_24c;
      local_278 = local_248;
      pbVar11 = (byte *)FUN_80291344(unaff_r22,unaff_r23,(int)pcVar12,(char *)&local_284);
    }
    else {
      local_294 = local_254;
      local_290 = local_250;
      local_28c = local_24c;
      local_288 = local_248;
      pbVar11 = (byte *)FUN_80291620(unaff_r28,(int)pcVar12,(char *)&local_294);
    }
    if (pbVar11 == (byte *)0x0) {
LAB_80290650:
      iVar3 = FUN_80292004((int)pcVar2);
      if (iVar3 == 0) {
        return iVar14 + iVar3;
      }
      iVar4 = (*(code *)param_1)(param_2,pcVar2);
      if (iVar4 != 0) {
        return iVar14 + iVar3;
      }
      return -1;
    }
    pcVar2 = acStack_45 + -(int)pbVar11;
  }
LAB_80290690:
  pcVar13 = pcVar2;
  if (local_254._0_1_ != '\0') {
    local_2b7[0] = ' ';
    if (local_254._0_1_ == '\x02') {
      local_2b7[0] = '0';
    }
    bVar1 = *pbVar11;
    if ((((bVar1 == 0x2b) || (bVar1 == 0x2d)) || (bVar1 == 0x20)) && (local_2b7[0] == '0')) {
      iVar3 = (*(code *)param_1)(param_2,pbVar11,1);
      if (iVar3 == 0) {
        return -1;
      }
      pbVar11 = pbVar11 + 1;
      pcVar13 = pcVar2 + -1;
    }
    for (; (int)pcVar2 < local_24c; pcVar2 = pcVar2 + 1) {
      iVar3 = (*(code *)param_1)(param_2,local_2b7,1);
      if (iVar3 == 0) {
        return -1;
      }
    }
  }
  if ((pcVar13 != (char *)0x0) && (iVar3 = (*(code *)param_1)(param_2,pbVar11,pcVar13), iVar3 == 0))
  {
    return -1;
  }
  if (local_254._0_1_ == '\0') {
    for (; (int)pcVar2 < local_24c; pcVar2 = pcVar2 + 1) {
      local_2b8 = 0x20;
      iVar3 = (*(code *)param_1)(param_2,&local_2b8,1);
      if (iVar3 == 0) {
        return -1;
      }
    }
  }
  iVar14 = iVar14 + (int)pcVar2;
  goto LAB_802907d0;
}

