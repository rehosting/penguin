import ast
from penguin import Plugin, plugins, yaml, getColoredLogger

#class HandleYield(NodeTransformer):
#        def visit_Yield(self, node):
#        
#        def visit_YieldFrom(self,node):



class Repl(Plugin):

    def __init__(self,panda):
        self.panda = panda
        self.locals = None
        self.logger = getColoredLogger("plugins.repl")

    def code(self,test_string,local=None):
        if local == None:
            local = self.locals
        test = input(">")
        self.logger.info(test)
        print(test)
        tree = ast.parse(test,mode="single")
        print(ast.dump(tree))
        a = 0
        for node in ast.walk(tree):
            if isinstance(node, ast.Expr) and  isinstance(node.value, ast.YieldFrom) :
               a = yield from self.rewrite_yieldFrom(node.value,local)
        print(a)
        return a
    def rewrite_yieldFrom(self,node,local):
        node = ast.Expression(node.value)
        ast.fix_missing_locations(node)
        self.logger.info(ast.dump(node))
        c = compile(node,'<string>',mode='eval',optimize=0)
        result = eval(c,globals(),local)
        self.logger.info(result)
        return result
