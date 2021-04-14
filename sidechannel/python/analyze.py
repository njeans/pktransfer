import ast

class SideChannel(ast.NodeVisitor):
    def __init__(self):
        self.sidechannels_found = False
        super().__init__()

    def visit(self, node):
        if type(node) == ast.For or \
            type(node) == ast.AsyncFor or \
            type(node) == ast.While or \
            type(node) == ast.If or \
            type(node) == ast.Try or \
            type(node) == ast.Assert :
            self.sidechannels_found = True
            print("branch at line", node.lineno, node)

    def sidechannels(self):
        return self.sidechannels_found

def check(filename):
    with open(filename) as f:
        source = f.read()
    tree = ast.parse(source)
    checker = SideChannel()
    for node in tree.body:
        checker.visit(node)
    sidechannels = checker.sidechannels()
    return sidechannels

file1= "source_side_ex.py"
sidechannels1 = check(file1)
print(file1,"sidechannels",sidechannels1)

file2= "source_no_side.py"
sidechannels2 = check(file2)
print(file2,"sidechannels",sidechannels2)
