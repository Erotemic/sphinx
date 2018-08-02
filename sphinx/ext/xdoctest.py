from sphinx.builders import Builder


class XDocTestBuilder(Builder):
    """
    Runs test snippets in the documentation.
    """
    name = 'xdoctest'
    epilog = __('Testing of doctests in the sources finished, look at the '
                'results in %(outdir)s/output.txt.')

    def init(self):
        # type: () -> None
        # default options
        self.opt = self.config.doctest_default_flags

        # HACK HACK HACK
        # doctest compiles its snippets with type 'single'. That is nice
        # for doctest examples but unusable for multi-statement code such
        # as setup code -- to be able to use doctest error reporting with
        # that code nevertheless, we monkey-patch the "compile" it uses.
        doctest.compile = self.compile  # type: ignore

        sys.path[0:0] = self.config.doctest_path

        self.type = 'single'

        self.total_failures = 0
        self.total_tries = 0
        self.setup_failures = 0
        self.setup_tries = 0
        self.cleanup_failures = 0
        self.cleanup_tries = 0

        date = time.strftime('%Y-%m-%d %H:%M:%S')

        self.outfile = None  # type: IO
        self.outfile = codecs.open(path.join(self.outdir, 'output.txt'),  # type: ignore
                                   'w', encoding='utf-8')
        self.outfile.write(('Results of xdoctest builder run on %s\n'
                            '==================================%s\n') %
                           (date, '=' * len(date)))

    def _out(self, text):
        # type: (unicode) -> None
        logger.info(text, nonl=True)
        self.outfile.write(text)

    def _warn_out(self, text):
        # type: (unicode) -> None
        if self.app.quiet or self.app.warningiserror:
            logger.warning(text)
        else:
            logger.info(text, nonl=True)
        if isinstance(text, binary_type):
            text = force_decode(text, None)
        self.outfile.write(text)

    def get_target_uri(self, docname, typ=None):
        # type: (unicode, unicode) -> unicode
        return ''

    def get_outdated_docs(self):
        # type: () -> Set[unicode]
        return self.env.found_docs

    def finish(self):
        # type: () -> None
        # write executive summary
        def s(v):
            # type: (int) -> unicode
            return v != 1 and 's' or ''
        repl = (self.total_tries, s(self.total_tries),
                self.total_failures, s(self.total_failures),
                self.setup_failures, s(self.setup_failures),
                self.cleanup_failures, s(self.cleanup_failures))
        self._out(textwrap.dedent('''
            XDoctest summary
            ===============
            %5d test%s
            %5d failure%s in tests
            %5d failure%s in setup code
            %5d failure%s in cleanup code
            ''' % repl))
        self.outfile.close()

        if self.total_failures or self.setup_failures or self.cleanup_failures:
            self.app.statuscode = 1

    def write(self, build_docnames, updated_docnames, method='update'):
        # type: (Iterable[unicode], Sequence[unicode], unicode) -> None
        if build_docnames is None:
            build_docnames = sorted(self.env.all_docs)

        logger.info(bold('running tests...'))
        for docname in build_docnames:
            # no need to resolve the doctree
            doctree = self.env.get_doctree(docname)
            self.test_doc(docname, doctree)

    def get_filename_for_node(self, node, docname):
        # type: (nodes.Node, unicode) -> str
        """Try to get the file which actually contains the doctest, not the
        filename of the document it's included in."""
        try:
            filename = relpath(node.source, self.env.srcdir)\
                .rsplit(':docstring of ', maxsplit=1)[0]
        except Exception:
            filename = self.env.doc2path(docname, base=None)
        if PY2:
            return filename.encode(fs_encoding)
        return filename

    @staticmethod
    def get_line_number(node):
        # type: (nodes.Node) -> Optional[int]
        """Get the real line number or admit we don't know."""
        # TODO:  Work out how to store or calculate real (file-relative)
        #       line numbers for doctest blocks in docstrings.
        if ':docstring of ' in path.basename(node.source or ''):
            # The line number is given relative to the stripped docstring,
            # not the file.  This is correct where it is set, in
            # `docutils.nodes.Node.setup_child`, but Sphinx should report
            # relative to the file, not the docstring.
            return None
        if node.line is not None:
            # TODO: find the root cause of this off by one error.
            return node.line - 1
        return None

    def test_doc(self, docname, doctree):
        return
        # type: (unicode, nodes.Node) -> None
        groups = {}  # type: Dict[unicode, TestGroup]
        add_to_all_groups = []
        self.setup_runner = SphinxDocTestRunner(verbose=False,
                                                optionflags=self.opt)
        self.test_runner = SphinxDocTestRunner(verbose=False,
                                               optionflags=self.opt)
        self.cleanup_runner = SphinxDocTestRunner(verbose=False,
                                                  optionflags=self.opt)

        self.test_runner._fakeout = self.setup_runner._fakeout  # type: ignore
        self.cleanup_runner._fakeout = self.setup_runner._fakeout  # type: ignore

        if self.config.doctest_test_doctest_blocks:
            def condition(node):
                # type: (nodes.Node) -> bool
                return (isinstance(node, (nodes.literal_block, nodes.comment)) and
                        'testnodetype' in node) or \
                    isinstance(node, nodes.doctest_block)
        else:
            def condition(node):
                # type: (nodes.Node) -> bool
                return isinstance(node, (nodes.literal_block, nodes.comment)) \
                    and 'testnodetype' in node
        for node in doctree.traverse(condition):
            source = node['test'] if 'test' in node else node.astext()
            filename = self.get_filename_for_node(node, docname)
            line_number = self.get_line_number(node)
            if not source:
                logger.warning(__('no code/output in %s block at %s:%s'),
                               node.get('testnodetype', 'doctest'),
                               filename, line_number)
            code = TestCode(source, type=node.get('testnodetype', 'doctest'),
                            filename=filename, lineno=line_number,
                            options=node.get('options'))
            node_groups = node.get('groups', ['default'])
            if '*' in node_groups:
                add_to_all_groups.append(code)
                continue
            for groupname in node_groups:
                if groupname not in groups:
                    groups[groupname] = TestGroup(groupname)
                groups[groupname].add_code(code)
        for code in add_to_all_groups:
            for group in itervalues(groups):
                group.add_code(code)
        if self.config.doctest_global_setup:
            code = TestCode(self.config.doctest_global_setup,
                            'testsetup', filename=None, lineno=0)
            for group in itervalues(groups):
                group.add_code(code, prepend=True)
        if self.config.doctest_global_cleanup:
            code = TestCode(self.config.doctest_global_cleanup,
                            'testcleanup', filename=None, lineno=0)
            for group in itervalues(groups):
                group.add_code(code)
        if not groups:
            return

        self._out('\nDocument: %s\n----------%s\n' %
                  (docname, '-' * len(docname)))
        for group in itervalues(groups):
            self.test_group(group)
        # Separately count results from setup code
        res_f, res_t = self.setup_runner.summarize(self._out, verbose=False)
        self.setup_failures += res_f
        self.setup_tries += res_t
        if self.test_runner.tries:
            res_f, res_t = self.test_runner.summarize(self._out, verbose=True)
            self.total_failures += res_f
            self.total_tries += res_t
        if self.cleanup_runner.tries:
            res_f, res_t = self.cleanup_runner.summarize(self._out,
                                                         verbose=True)
            self.cleanup_failures += res_f
            self.cleanup_tries += res_t

    def compile(self, code, name, type, flags, dont_inherit):
        # type: (unicode, unicode, unicode, Any, bool) -> Any
        return compile(code, name, self.type, flags, dont_inherit)

    def test_group(self, group):
        # type: (TestGroup) -> None
        ns = {}  # type: Dict

        def run_setup_cleanup(runner, testcodes, what):
            # type: (Any, List[TestCode], Any) -> bool
            examples = []
            for testcode in testcodes:
                examples.append(doctest.Example(  # type: ignore
                    doctest_encode(testcode.code, self.env.config.source_encoding), '',  # type: ignore  # NOQA
                    lineno=testcode.lineno))
            if not examples:
                return True
            # simulate a doctest with the code
            sim_doctest = doctest.DocTest(examples, {},
                                          '%s (%s code)' % (group.name, what),
                                          testcodes[0].filename, 0, None)
            sim_doctest.globs = ns
            old_f = runner.failures
            self.type = 'exec'  # the snippet may contain multiple statements
            runner.run(sim_doctest, out=self._warn_out, clear_globs=False)
            if runner.failures > old_f:
                return False
            return True

        # run the setup code
        if not run_setup_cleanup(self.setup_runner, group.setup, 'setup'):
            # if setup failed, don't run the group
            return

        # run the tests
        for code in group.tests:
            if len(code) == 1:
                # ordinary doctests (code/output interleaved)
                try:
                    test = parser.get_doctest(  # type: ignore
                        doctest_encode(code[0].code, self.env.config.source_encoding), {},  # type: ignore  # NOQA
                        group.name, code[0].filename, code[0].lineno)
                except Exception:
                    logger.warning(__('ignoring invalid doctest code: %r'), code[0].code,
                                   location=(code[0].filename, code[0].lineno))
                    continue
                if not test.examples:
                    continue
                for example in test.examples:
                    # apply directive's comparison options
                    new_opt = code[0].options.copy()
                    new_opt.update(example.options)
                    example.options = new_opt
                self.type = 'single'  # as for ordinary doctests
            else:
                # testcode and output separate
                output = code[1] and code[1].code or ''
                options = code[1] and code[1].options or {}
                # disable <BLANKLINE> processing as it is not needed
                options[doctest.DONT_ACCEPT_BLANKLINE] = True
                # find out if we're testing an exception
                m = parser._EXCEPTION_RE.match(output)  # type: ignore
                if m:
                    exc_msg = m.group('msg')
                else:
                    exc_msg = None
                example = doctest.Example(  # type: ignore
                    doctest_encode(code[0].code, self.env.config.source_encoding), output,  # type: ignore  # NOQA
                    exc_msg=exc_msg,
                    lineno=code[0].lineno,
                    options=options)
                test = doctest.DocTest([example], {}, group.name,  # type: ignore
                                       code[0].filename, code[0].lineno, None)
                self.type = 'exec'  # multiple statements again
            # DocTest.__init__ copies the globs namespace, which we don't want
            test.globs = ns
            # also don't clear the globs namespace after running the doctest
            self.test_runner.run(test, out=self._warn_out, clear_globs=False)

        # run the cleanup
        run_setup_cleanup(self.cleanup_runner, group.cleanup, 'cleanup')


def setup(app):
    # type: (Sphinx) -> Dict[unicode, Any]
    # app.add_directive('testsetup', TestsetupDirective)
    # app.add_directive('testcleanup', TestcleanupDirective)
    # app.add_directive('doctest', DoctestDirective)
    # app.add_directive('testcode', TestcodeDirective)
    # app.add_directive('testoutput', TestoutputDirective)
    app.add_builder(XDocTestBuilder)
    # this config value adds to sys.path
    # app.add_config_value('doctest_path', [], False)
    # app.add_config_value('doctest_test_doctest_blocks', 'default', False)
    # app.add_config_value('doctest_global_setup', '', False)
    # app.add_config_vadlue('doctest_global_cleanup', '', False)
    # app.add_config_value(
    #     'doctest_default_flags',
    #     doctest.DONT_ACCEPT_TRUE_FOR_1 | doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL,
    #     False)
    return {'version': sphinx.__display_version__, 'parallel_read_safe': True}
