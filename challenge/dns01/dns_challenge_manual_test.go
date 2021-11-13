package dns01

import (
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDNSProviderManual(t *testing.T) {
	backupStdin := os.Stdin
	defer func() { os.Stdin = backupStdin }()

	testCases := []struct {
		desc        string
		input       string
		expectError bool
	}{
		{
			desc:  "Press enter",
			input: "ok\n",
		},
		{
			desc:        "Missing enter",
			input:       "ok",
			expectError: true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			file, err := ioutil.TempFile("", "lego_test")
			assert.NoError(t, err)
			defer func() { _ = os.Remove(file.Name()) }()

			_, err = io.WriteString(file, test.input)
			assert.NoError(t, err)

			_, err = file.Seek(0, io.SeekStart)
			assert.NoError(t, err)

			os.Stdin = file

			manualProvider, err := NewDNSProviderManual()
			require.NoError(t, err)

			err = manualProvider.Present("example.com", "", "")
			if test.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				err = manualProvider.CleanUp("example.com", "", "")
				require.NoError(t, err)
			}
		})
	}
}

func BenchmarkDNSProviderManual(b *testing.B) {
	for n := 0; n < b.N; n++ {
		backupStdin := os.Stdin
		defer func() { os.Stdin = backupStdin }()

		testCases := []struct {
			desc        string
			input       string
			expectError bool
		}{
			{
				desc:  "Press enter",
				input: "ok\n",
			},
			{
				desc:        "Missing enter",
				input:       "ok",
				expectError: true,
			},
		}

		for _, test := range testCases {
			b.Run(test.desc, func(b *testing.B) {
				file, err := ioutil.TempFile("", "lego_test")
				assert.NoError(b, err)
				defer func() { _ = os.Remove(file.Name()) }()

				_, err = io.WriteString(file, test.input)
				assert.NoError(b, err)

				_, err = file.Seek(0, io.SeekStart)
				assert.NoError(b, err)

				os.Stdin = file

				manualProvider, err := NewDNSProviderManual()
				require.NoError(b, err)

				err = manualProvider.Present("example.com", "", "")
				if test.expectError {
					require.Error(b, err)
				} else {
					require.NoError(b, err)

					err = manualProvider.CleanUp("example.com", "", "")
					require.NoError(b, err)
				}
			})
		}
	}
}
