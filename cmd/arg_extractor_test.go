package cmd

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/urfave/cli"
)

func TestPositionalArgsPresent(t *testing.T) {
	ctx := createContext(
		createFlagSet(),
		[]string{"MyArg"})
	extractor := NewArgExtractor(ctx)
	require.Equal(t, true, extractor.PositionalArgsPresent())
}

func TestPositionalArgsPresent_NotPresent(t *testing.T) {
	ctx := createContext(
		createFlagSet(),
		[]string{})
	extractor := NewArgExtractor(ctx)
	require.Equal(t, false, extractor.PositionalArgsPresent())
}

func TestStringArg_PositionalArg(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{"MyDest"})
	require.Equal(t, 1, len(extractor.args))

	arg, err := extractor.StringArg("dest")
	require.NoError(t, err)
	require.Equal(t, "MyDest", arg)
	require.Equal(t, 0, len(extractor.args))
}

func TestStringArg_Flag(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{"--dest", "MyDest", "MyOtherDest"})
	require.Equal(t, 1, len(extractor.args))

	arg, err := extractor.StringArg("dest")
	require.NoError(t, err)
	require.Equal(t, "MyDest", arg)
	require.Equal(t, 1, len(extractor.args))
}

func TestStringArg_Missing(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{})
	require.Equal(t, 0, len(extractor.args))

	_, err := extractor.StringArg("dest")
	require.Error(t, err)
	require.Equal(t, 0, len(extractor.args))
}

func TestStringArgWithDefault_PositionalArg(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{"MyDest"})
	require.Equal(t, 1, len(extractor.args))

	arg := extractor.StringArgWithDefault("dest", "DEFAULT")
	require.Equal(t, "MyDest", arg)
	require.Equal(t, 0, len(extractor.args))
}

func TestStringArgWithDefault_Flag(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{"--dest", "MyDest", "MyOtherDest"})
	require.Equal(t, 1, len(extractor.args))

	arg := extractor.StringArgWithDefault("dest", "DEFAULT")
	require.Equal(t, "MyDest", arg)
	require.Equal(t, 1, len(extractor.args))
}

func TestStringArgWithDefault_Missing(t *testing.T) {
	extractor := createStringFlagArgExtractor(
		"dest", []string{})
	require.Equal(t, 0, len(extractor.args))

	arg := extractor.StringArgWithDefault("dest", "DEFAULT")
	require.Equal(t, "DEFAULT", arg)
	require.Equal(t, 0, len(extractor.args))
}

func TestTypedArg_PositionalArgs(t *testing.T) {
	extractor := createMultiArgExtractor(
		[]string{"strval", "012abc", "789", "20.67"})
	require.Equal(t, 4, len(extractor.args))
	verifyTypedArgs(t, &extractor)
	require.Equal(t, 0, len(extractor.args))
}

func TestTypedArg_Flags(t *testing.T) {
	extractor := createMultiArgExtractor([]string{
		"--string_arg", "strval",
		"--hex_arg", "012abc",
		"--int64_arg", "789",
		"--float64_arg", "20.67"})
	verifyTypedArgs(t, &extractor)
	require.Equal(t, 0, len(extractor.args))
}

// Verify that errors are generated when args are missing.
func TestTypedArgs_Missing(t *testing.T) {
	extractor := createMultiArgExtractor([]string{})
	require.Equal(t, 0, len(extractor.args))

	_, err := extractor.StringArg("string_arg")
	require.Equal(t, &MissingArgError{"string_arg"}, err)
	require.Equal(t, "string_arg argument missing", err.Error())

	_, err = extractor.HexArg("hex_arg")
	require.Equal(t, &MissingArgError{"hex_arg"}, err)
	_, err = extractor.Int64Arg("int64_arg")
	require.Equal(t, &MissingArgError{"int64_arg"}, err)
	_, err = extractor.Float64Arg("float64_arg")
	require.Equal(t, &MissingArgError{"float64_arg"}, err)

	require.Equal(t, 0, len(extractor.args))
}

// Verify that errors are generated for type of positional arg when
// invalid values are specified.
func TestTypedArg_InvalidPositionalArgs(t *testing.T) {
	extractor := createMultiArgExtractor(
		[]string{"20.67", "012abc", "NonFloatText"})

	verifyInvalidTypedArgs(t, extractor)
}

// Verify that errors are generated for type of flag when
// invalid values are specified.
func TestTypedArg_InvalidFlags(t *testing.T) {
	extractor := createMultiArgExtractor([]string{
		"--hex_arg", "20.67",
		"--int64_arg", "012abc",
		"--float64_arg", "NonFloatText"})

	verifyInvalidTypedArgs(t, extractor)
}

// Verify that each type of positional arg can be extracted successfully.
func TestTypedArgWithDefault_PositionalArg(t *testing.T) {
	extractor := createMultiArgExtractor(
		[]string{"strval", "012abc", "789", "20.67"})
	verifyTypedArgsWithDefault(t, extractor)
}

// Verify that each type of flag can be extracted successfully.
func TestTypedArgWithDefault_Flag(t *testing.T) {
	extractor := createMultiArgExtractor([]string{
		"--string_arg", "strval",
		"--hex_arg", "012abc",
		"--int64_arg", "789",
		"--float64_arg", "20.67"})
	verifyTypedArgsWithDefault(t, extractor)
}

func TestTypedArgWithDefault_Missing(t *testing.T) {
	extractor := createMultiArgExtractor([]string{})
	require.Equal(t, 0, len(extractor.args))

	argStr := extractor.StringArgWithDefault("string_arg", "DEFAULT")
	require.Equal(t, "DEFAULT", argStr)

	argHex, err := extractor.HexArgWithDefault("hex_arg", []byte{0xfe, 0x01})
	require.NoError(t, err)
	require.Equal(t, []byte{0xfe, 0x01}, argHex)

	argInt64, err := extractor.Int64ArgWithDefault("int64_arg", 98765)
	require.NoError(t, err)
	require.Equal(t, int64(98765), argInt64)

	argFloat64, err := extractor.Float64ArgWithDefault("float64_arg", 12.4)
	require.NoError(t, err)
	require.Equal(t, 12.4, argFloat64)

	require.Equal(t, 0, len(extractor.args))
}

func TestTypedArgWithDefault_InvalidPositionalArgs(t *testing.T) {
	extractor := createMultiArgExtractor(
		[]string{"20.67", "012abc", "NonFloatText"})
	verifyInvalidTypedArgsWithDefault(t, extractor)
}

func TestTypedArgWithDefault_InvalidFlags(t *testing.T) {
	extractor := createMultiArgExtractor([]string{
		"--hex_arg", "20.67",
		"--int64_arg", "012abc",
		"--float64_arg", "NonFloatText"})
	verifyInvalidTypedArgsWithDefault(t, extractor)
}

// Verify that each type of argument can be extracted successfully.
func verifyTypedArgs(t *testing.T, extractor *ArgExtractor) {
	argStr, err := extractor.StringArg("string_arg")
	require.NoError(t, err)
	require.Equal(t, "strval", argStr)

	argHex, err := extractor.HexArg("hex_arg")
	require.NoError(t, err)
	require.Equal(t, []byte{0x1, 0x2a, 0xbc}, argHex)

	argInt64, err := extractor.Int64Arg("int64_arg")
	require.NoError(t, err)
	require.Equal(t, int64(789), argInt64)

	argFloat64, err := extractor.Float64Arg("float64_arg")
	require.NoError(t, err)
	require.Equal(t, 20.67, argFloat64)
}

// Verify that defaults are ignored for each type of argument
// when values are provided by the user.
func verifyTypedArgsWithDefault(t *testing.T, extractor ArgExtractor) {
	argStr := extractor.StringArgWithDefault("string_arg", "BadDefault")
	require.Equal(t, "strval", argStr)

	argHex, err := extractor.HexArgWithDefault("hex_arg", []byte{0xba, 0xdd, 0xef})
	require.NoError(t, err)
	require.Equal(t, []byte{0x1, 0x2a, 0xbc}, argHex)

	argInt64, err := extractor.Int64ArgWithDefault("int64_arg", 666)
	require.NoError(t, err)
	require.Equal(t, int64(789), argInt64)

	argFloat64, err := extractor.Float64ArgWithDefault("float64_arg", 666.666)
	require.NoError(t, err)
	require.Equal(t, 20.67, argFloat64)
}

func verifyInvalidTypedArgs(t *testing.T, extractor ArgExtractor) {
	_, err := extractor.HexArg("hex_arg")
	require.Error(t, err)
	require.Equal(t,
		"unable to parse hex_arg (value '20.67'): encoding/hex: invalid byte: U+002E '.'",
		err.Error())

	_, err = extractor.Int64Arg("int64_arg")
	require.Error(t, err)
	_, err = extractor.Float64Arg("float64_arg")
	require.Error(t, err)
}

func verifyInvalidTypedArgsWithDefault(
	t *testing.T, extractor ArgExtractor) {

	_, err := extractor.HexArgWithDefault("hex_arg", []byte{})
	require.Error(t, err)
	_, err = extractor.Int64ArgWithDefault("int64_arg", 0)
	require.Error(t, err)
	_, err = extractor.Float64ArgWithDefault("float64_arg", 0)
	require.Error(t, err)
}

// A minimal ArgExtractor for testing a single flag at a time.
func createStringFlagArgExtractor(
	flagName string, args []string) ArgExtractor {

	set := createFlagSet()
	set.String(flagName, "", "doc")
	return NewArgExtractor(createContext(set, args))
}

// An ArgExtractor for testing every type of flag at the same type.
func createMultiArgExtractor(args []string) ArgExtractor {
	set := createFlagSet()
	// Use all strings since we don't use the cli library to handle types.
	set.String("string_arg", "", "doc")
	set.String("hex_arg", "", "doc")
	set.String("int64_arg", "", "doc")
	set.String("float64_arg", "", "doc")
	return NewArgExtractor(createContext(set, args))
}

func createContext(set *flag.FlagSet, args []string) *cli.Context {
	ctx := cli.NewContext(nil, set, nil)
	set.Parse(args)
	return ctx
}

func createFlagSet() *flag.FlagSet {
	return flag.NewFlagSet("test", 0)
}
