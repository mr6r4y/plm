local dap = require("dap")

dap.adapters.gdb = function(cb, config)
	cb({
		id = "gdb",
		type = "executable",
		command = vim.fs.normalize("~/apps/binutils-gdb/bin/gdb"),
		args = { "--quiet", "--interpreter=dap" },
	})
end

dap.adapters.codelldb = function(cb, config)
	cb({
		id = "codelldb",
		type = "executable",
		command = "codelldb",
	})
end

dap.configurations.c = {
	{
		-- The first three options are required by nvim-dap
		type = "codelldb", -- the type here established the link to the adapter definition: `dap.adapters.python`
		request = "launch",
		name = "plm_bs-test",

		program = vim.fs.normalize("build/Debug/plm_bs-test"), -- This configuration will launch the current file if used
	},
}
