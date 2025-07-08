import { createSlice, PayloadAction } from "@reduxjs/toolkit";

// ✅ Define the interface for the state
interface IDisplay {
  isAuthModalOpen: boolean;
  isBackendUp: boolean;
  numThreats : number
}

// ✅ Define the initial state
const initialState: IDisplay = {
  isAuthModalOpen: false,
  isBackendUp:false,
  numThreats:0,
};

// ✅ Create the slice
const displaySlice = createSlice({
  name: "display",
  initialState,
  reducers: {
    setAuthModalState: (state, action: PayloadAction<boolean>) => {
      state.isAuthModalOpen = action.payload;
    },
    setIsBackendUp :(state, action:PayloadAction<boolean>) =>{
      state.isBackendUp = action.payload
    },
    addThreats:(state, action:PayloadAction<number>) =>{
      state.numThreats += action.payload
    }
  },
});


// ✅ Export actions and reducer
export const { setAuthModalState, setIsBackendUp, addThreats } = displaySlice.actions;
export default displaySlice.reducer
