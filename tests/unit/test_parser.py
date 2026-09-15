from jsxray.javascript.parser import JSParser


def test_tree_sitter_modern_syntax():
    code = """
    // Optional chaining, nullish coalescing, arrow functions, async/await
    const getUser = async (id) => {
        const response = await fetch(`/api/users/${id}`);
        const data = await response?.json() ?? {};
        return data;
    };
    """
    parser = JSParser()
    tree, err = parser.parse(code)
    assert err is None
    assert tree is not None
    assert tree.root_node.type == "program"
