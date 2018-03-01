package cmd

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/urfave/cli"
)

// ArgExtractor allows processing of positional and flag arguments
// in a unified manner and manages the state of arguments consumed.
type ArgExtractor struct {
	ctx  *cli.Context
	args cli.Args
}

// NewArgExtractor creates an ArgExtractor fully initialized from a Context.
func NewArgExtractor(ctx *cli.Context) ArgExtractor {
	return ArgExtractor{ctx, ctx.Args()}
}

// PositionalArgsPresent returns true if there are any positional args left
// to consume.
func (e *ArgExtractor) PositionalArgsPresent() bool {
	return e.args.Present()
}

// StringArg extracts a single flag of the specified name,
// or positional argument if a flag isn't provided.
// Positional arguments are consumed such that they cannot be used again.
// A MissingArgError is returned if no argument is available.
func (e *ArgExtractor) StringArg(argName string) (string, error) {
	var value string
	if e.ctx.IsSet(argName) {
		value = e.ctx.String(argName)
	} else if e.args.Present() {
		value = e.args.First()
		// Remove the positional argument that was just consumed.
		e.args = e.args.Tail()
	} else {
		return "", &MissingArgError{argName}
	}

	return value, nil
}

// StringArgWithDefault is the same as StringArg, except a default value
// is returned in the case of a missing argument.
func (e *ArgExtractor) StringArgWithDefault(
	argName string, defaultValue string) string {

	arg, err := e.StringArg(argName)
	// If a error occurred, it was a MissingArgError, so return the default.
	if err != nil {
		return defaultValue
	}

	return arg
}

// HexArg extracts a single flag or positional argument as a hex []byte,
// returning a MissingArgError if no argument is available,
// or a ParseError if the argument is not in a hexadecimal format.
func (e *ArgExtractor) HexArg(argName string) ([]byte, error) {
	arg, err := e.typedArg(argName, []byte{}, hexParser)
	return arg.([]byte), err
}

// Int64Arg processes a single flag or positional argument as an int64,
// returning a MissingArgError if no argument is available,
// or a ParseError if the argument is not in a hexadecimal format.
func (e *ArgExtractor) Int64Arg(argName string) (int64, error) {
	arg, err := e.typedArg(argName, int64(0), int64Parser)
	return arg.(int64), err
}

// Float64Arg extracts a single flag or positional argument as an float64,
// returning a MissingArgError if no argument is available,
// or a ParseError if the argument is not in an floating point format.
func (e *ArgExtractor) Float64Arg(argName string) (float64, error) {
	arg, err := e.typedArg(argName, 0.0, float64Parser)
	return arg.(float64), err
}

// HexArgWithDefault is the same as HexArg, except a default value
// is returned in the case of a missing argument.
func (e *ArgExtractor) HexArgWithDefault(
	argName string, defaultValue []byte) ([]byte, error) {

	arg, err := e.typedArg(argName, []byte{}, hexParser)

	_, isMissingArgErr := err.(*MissingArgError)
	if isMissingArgErr {
		return defaultValue, nil
	}

	return arg.([]byte), err
}

// Int64ArgWithDefault is the same as Int64Arg, except a default value
// is returned in the case of a missing argument.
func (e *ArgExtractor) Int64ArgWithDefault(
	argName string, defaultValue int64) (int64, error) {

	arg, err := e.typedArg(argName, int64(0), int64Parser)

	_, isMissingArgErr := err.(*MissingArgError)
	if isMissingArgErr {
		return defaultValue, nil
	}

	return arg.(int64), err
}

// Float64ArgWithDefault is the same as Float64Arg, except a default value
// is returned in the case of a missing argument.
func (e *ArgExtractor) Float64ArgWithDefault(
	argName string, defaultValue float64) (float64, error) {

	arg, err := e.typedArg(argName, 0.0, float64Parser)

	_, isMissingArgErr := err.(*MissingArgError)
	if isMissingArgErr {
		return defaultValue, nil
	}

	return arg.(float64), err
}

// typedArg extracts a single flag of any type, using the given parser.
func (e *ArgExtractor) typedArg(
	argName string,
	defaultValue interface{},
	parser func(string) (interface{}, error)) (interface{}, error) {

	argStr, err := e.StringArg(argName)
	if err != nil {
		return defaultValue, err
	}

	arg, err := parser(argStr)
	if err != nil {
		return defaultValue, &ParseError{argName, argStr, err}
	}

	return arg, nil
}

func int64Parser(str string) (interface{}, error) {
	return strconv.ParseInt(str, 10, 64)
}

func float64Parser(str string) (interface{}, error) {
	return strconv.ParseFloat(str, 64)
}

func hexParser(str string) (interface{}, error) {
	return hex.DecodeString(str)
}

// MissingArgError occurs when a necessary argument is not provided.
type MissingArgError struct {
	ArgName string
}

func (err *MissingArgError) Error() string {
	return err.ArgName + " argument missing"
}

// ParseError occurs when an argument is provided in a bad format.
type ParseError struct {
	ArgName    string
	BadValue   string
	InnerError error
}

func (err *ParseError) Error() string {
	return fmt.Sprintf(
		"unable to parse %s (value '%s'): %v",
		err.ArgName,
		err.BadValue,
		err.InnerError)
}
