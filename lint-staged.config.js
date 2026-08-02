export default {
	"apps/server/**/*.rs": () =>
		"cargo fmt --manifest-path apps/server/Cargo.toml --all",
};
