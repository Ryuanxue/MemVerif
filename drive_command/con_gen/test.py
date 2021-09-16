import os
import subprocess

from pycparser import c_parser, parse_file, c_ast, c_generator

generator = c_generator.CGenerator()

l=list(range(1,10))
print(l)
print(l[2:])

parser = c_parser.CParser()
fake_include = "../../utils/fake_libc_include"
abs_fake_include = os.path.abspath(fake_include)
command1 = "gcc -E ctest.c  -I" + abs_fake_include +">fun"
(status, output) = subprocess.getstatusoutput(command1)
if status == 0:
    ast = parse_file("fun", use_cpp=True)
print(ast)
labelst=c_ast.Label(name="err",stmt=c_ast.FuncCall(name=c_ast.ID(name="printf") ,args=c_ast.ExprList(exprs=[c_ast.Constant(type="string",value='"##"')])))
print(labelst)
print(generator.visit(labelst))
