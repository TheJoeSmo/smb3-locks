; Original address was $B3A8
; 1-6
    .word $0000 ; Alternate level layout
    .word $0000 ; Alternate object layout
    .byte LEVEL1_SIZE_10 | LEVEL1_YSTART_170
    .byte LEVEL2_BGPAL_00 | LEVEL2_OBJPAL_08 | LEVEL2_XSTART_18 | LEVEL2_UNUSEDFLAG
    .byte LEVEL3_TILESET_01 | LEVEL3_VSCROLL_LOCKLOW | LEVEL3_PIPENOTEXIT
    .byte 4 & %00011111 | LEVEL4_INITACT_NOTHING
    .byte LEVEL5_BGM_ATHLETIC | LEVEL5_TIME_300

    .byte $19, $00, $10, $06, $1A, $01, $04, $18, $02, $42, $1A, $04, $04, $12, $06, $01
    .byte $14, $0B, $01, $17, $08, $22, $19, $09, $04, $15, $0E, $22, $17, $0F, $04, $30
    .byte $11, $82, $12, $11, $42, $13, $11, $10, $02, $14, $12, $04, $13, $17, $01, $19
    .byte $18, $10, $02, $35, $19, $01, $1A, $19, $04, $13, $1B, $10, $02, $12, $1C, $40
    .byte $14, $1C, $04, $17, $22, $A1, $16, $22, $B1, $13, $22, $A1, $12, $21, $07, $19
    .byte $24, $07, $34, $27, $61, $09, $2A, $01, $16, $2B, $10, $03, $13, $2C, $61, $17
    .byte $2C, $04, $10, $2F, $01, $37, $32, $30, $38, $32, $10, $33, $33, $13, $19, $32
    .byte $66, $33, $35, $0B, $18, $33, $42, $37, $37, $0A, $38, $37, $10, $05, $38, $01
    .byte $19, $3B, $10, $03, $16, $3C, $61, $1A, $3C, $04, $12, $40, $02, $13, $40, $10
    .byte $07, $19, $40, $10, $02, $18, $41, $40, $1A, $41, $04, $12, $47, $03, $11, $47
    .byte $10, $02, $12, $48, $04, $38, $4A, $40, $10, $4B, $02, $11, $4B, $10, $06, $10
    .byte $4D, $42, $18, $4C, $07, $18, $4D, $87, $19, $55, $A0, $19, $56, $82, $16, $5A
    .byte $E1, $16, $5B, $D0, $17, $5C, $B2, $11, $60, $E1, $10, $61, $83, $11, $65, $A1
    .byte $10, $51, $03, $2A, $55, $82, $07, $56, $01, $14, $58, $01, $28, $5A, $82, $31
    .byte $5E, $80, $27, $5F, $82, $33, $5A, $81, $09, $60, $01, $16, $61, $01, $03, $66
    .byte $01, $14, $68, $01, $16, $6E, $00, $33, $6A, $42, $26, $66, $82, $26, $6A, $82
    .byte $27, $6F, $82, $08, $71, $01, $2A, $74, $82, $0F, $74, $01, $18, $73, $00, $10
    .byte $7B, $00, $15, $7C, $00, $10, $78, $07, $1A, $7C, $07, $11, $79, $A0, $12, $79
    .byte $90, $13, $7A, $A0, $14, $7A, $B0, $15, $7A, $A3, $19, $7D, $B0, $13, $83, $01
    .byte $1A, $84, $10, $1F, $16, $87, $01, $19, $87, $42, $09, $08, $00, $0A, $12, $00
    .byte $05, $1C, $00, $07, $24, $00, $0A, $32, $00, $07, $3C, $00, $40, $8B, $09, $FF
