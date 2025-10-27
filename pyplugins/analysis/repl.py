import ast
from penguin import Plugin, plugins, yaml, getColoredLogger

class HandleYield(ast.NodeTransformer):
        def visit_Yield(self, node):
            #node =  self.generic_visit(node)
            result =  plugins.repl.push_node(node)
            return ast.Name('yield_result', ast.Load())


        def visit_YieldFrom(self,node):
            #node =  self.generic_visit(node)
            plugins.repl.push_node(node)
            return ast.Name('yield_result', ast.Load())


        #convert the NodeTransformer functions to generators   
        def generic_visit(self, node):
            for field, old_value in ast.iter_fields(node):
                if isinstance(old_value, list):
                    new_values = []
                    for value in old_value:
                        if isinstance(value, ast.AST):
                            value = self.visit(value)
                            if value is None:
                                continue
                            elif not isinstance(value, ast.AST):
                                new_values.extend(value)
                                continue
                        new_values.append(value)
                    old_value[:] = new_values
                elif isinstance(old_value, ast.AST):
                    new_node = self.visit(old_value)
                    if new_node is None:
                        delattr(node, field)
                    else:
                        setattr(node, field, new_node)
            return node
        
        def visit(self, node):
            """Visit a node."""
            method = 'visit_' + node.__class__.__name__
            visitor = getattr(self, method, self.generic_visit)
            return visitor(node)



class Repl(Plugin):

    def __init__(self,panda):
        self.panda = panda
        self.locals = None
        self.logger = getColoredLogger("plugins.repl")
        self.node = None

    def update_locals(self,local):
        if local == None:
            return
        if self.locals == None:
            self.locals = local
            return
        for key in local.keys():
            self.locals[key] = local[key]
    def code(self,test_string,local=None):
        self.update_locals(local)
        test = input(">")
        self.logger.info(test)
        print(test)
        tree = ast.parse(test,mode="single")
        print(ast.dump(tree))
        result =  HandleYield().visit(tree)
        result = ast.fix_missing_locations(result)
        print(result)
        if self.node != None:
            yield from self.eval_node()
        c = compile(result,'<string>',mode='single',optimize=0)
        return exec(c,globals(),self.locals)
    def push_node(self,node):
        self.node = node
    def eval_node(self):
        if self.node == None:
            return
        node = ast.Expression(self.node.value)
        self.node = None
        node = ast.fix_missing_locations(node)
        self.logger.info(ast.dump(node))
        c = compile(node,'<string>',mode='eval',optimize=0)
        result = yield from eval(c,globals(),self.locals)
        self.logger.info(result)
        new_locals = {"yield_result": result}
        plugins.repl.update_locals(new_locals)
        return result
