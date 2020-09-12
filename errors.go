package gopssst

import (
	"fmt"
)

type PSSSTError struct {
	message string
}

func (e *PSSSTError) Error() string {
	return fmt.Sprintf("PSSST Error: %s", e.message)
}
