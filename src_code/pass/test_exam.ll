; ModuleID = 'test_exam.c'
source_filename = "test_exam.c"
target datalayout = "e-m:e-p:32:32-p270:32:32-p271:32:32-p272:64:64-f64:32:64-f80:32-n8:16:32-S128"
target triple = "i386-unknown-linux-gnu"

%struct.test = type { i32, i32, i8*, i8*, %struct.subtest* }
%struct.subtest = type { i32, i32, i8* }

@.str = private unnamed_addr constant [3 x i8] c"%d\00", align 1

; Function Attrs: noinline nounwind optnone
define dso_local void @fuzztest(%struct.test* %arg1, i32 %arg2) #0 !dbg !8 {
entry:
  %arg1.addr = alloca %struct.test*, align 4
  %arg2.addr = alloca i32, align 4
  store %struct.test* %arg1, %struct.test** %arg1.addr, align 4
  call void @llvm.dbg.declare(metadata %struct.test** %arg1.addr, metadata !31, metadata !DIExpression()), !dbg !32
  store i32 %arg2, i32* %arg2.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %arg2.addr, metadata !33, metadata !DIExpression()), !dbg !34
  ret void, !dbg !35
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone
define dso_local i32 @main() #0 !dbg !36 {
entry:
  %call = call i32 (i8*, ...) @printf(i8* getelementptr inbounds ([3 x i8], [3 x i8]* @.str, i32 0, i32 0), i32 12), !dbg !39
  ret i32 0, !dbg !40
}

declare dso_local i32 @printf(i8*, ...) #2

attributes #0 = { noinline nounwind optnone "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="pentium4" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="pentium4" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!3, !4, !5, !6}
!llvm.ident = !{!7}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 12.0.0", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "test_exam.c", directory: "/home/raoxue/Desktop/MemVerif/src_code/pass")
!2 = !{}
!3 = !{i32 1, !"NumRegisterParameters", i32 0}
!4 = !{i32 7, !"Dwarf Version", i32 4}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !{i32 1, !"wchar_size", i32 4}
!7 = !{!"clang version 12.0.0"}
!8 = distinct !DISubprogram(name: "fuzztest", scope: !1, file: !1, line: 4, type: !9, scopeLine: 4, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!9 = !DISubroutineType(types: !10)
!10 = !{null, !11, !16}
!11 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !12, size: 32)
!12 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "test", file: !13, line: 9, size: 160, elements: !14)
!13 = !DIFile(filename: "./test_exam.h", directory: "/home/raoxue/Desktop/MemVerif/src_code/pass")
!14 = !{!15, !17, !18, !21, !22}
!15 = !DIDerivedType(tag: DW_TAG_member, name: "high", scope: !12, file: !13, line: 11, baseType: !16, size: 32)
!16 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_member, name: "b", scope: !12, file: !13, line: 12, baseType: !16, size: 32, offset: 32)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "str1", scope: !12, file: !13, line: 13, baseType: !19, size: 32, offset: 64)
!19 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !20, size: 32)
!20 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "str2", scope: !12, file: !13, line: 14, baseType: !19, size: 32, offset: 96)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "stu", scope: !12, file: !13, line: 15, baseType: !23, size: 32, offset: 128)
!23 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !24, size: 32)
!24 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !25)
!25 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "subtest", file: !13, line: 3, size: 96, elements: !26)
!26 = !{!27, !28, !30}
!27 = !DIDerivedType(tag: DW_TAG_member, name: "sub1", scope: !25, file: !13, line: 5, baseType: !16, size: 32)
!28 = !DIDerivedType(tag: DW_TAG_member, name: "sub2", scope: !25, file: !13, line: 6, baseType: !29, size: 32, offset: 32)
!29 = !DIBasicType(name: "long int", size: 32, encoding: DW_ATE_signed)
!30 = !DIDerivedType(tag: DW_TAG_member, name: "substr1", scope: !25, file: !13, line: 7, baseType: !19, size: 32, offset: 64)
!31 = !DILocalVariable(name: "arg1", arg: 1, scope: !8, file: !1, line: 4, type: !11)
!32 = !DILocation(line: 4, column: 28, scope: !8)
!33 = !DILocalVariable(name: "arg2", arg: 2, scope: !8, file: !1, line: 4, type: !16)
!34 = !DILocation(line: 4, column: 37, scope: !8)
!35 = !DILocation(line: 8, column: 1, scope: !8)
!36 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 10, type: !37, scopeLine: 11, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!37 = !DISubroutineType(types: !38)
!38 = !{!16}
!39 = !DILocation(line: 12, column: 2, scope: !36)
!40 = !DILocation(line: 13, column: 1, scope: !36)
